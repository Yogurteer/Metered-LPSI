#include "cx_oprf.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <libOTe/TwoChooseOne/Kos/KosOtExtSender.h>
#include <libOTe/TwoChooseOne/Kos/KosOtExtReceiver.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <macoro/sync_wait.h>
#include <macoro/when_all.h>
#include <algorithm>
#include <chrono>
#include <cstring>
#include <exception>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <set>
#include <stdexcept>
#include <thread>
#include <omp.h>
#include <cstdlib>

namespace cx {
static int thread_limit=1;
void set_thread_limit(int threads){if(threads<1)throw std::runtime_error("thread limit");thread_limit=threads;}
using Clock=std::chrono::steady_clock;
static double ms(Clock::time_point t) { return std::chrono::duration<double,std::milli>(Clock::now()-t).count(); }
static void require(bool ok,const char* s) { if(!ok) throw std::runtime_error(s); }
static int parallel_threads(std::size_t n, int desired) {
    return std::max(1,std::min(desired,static_cast<int>(std::max<std::size_t>(1,n/16))));
}
struct Context {
    EC_GROUP* group=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx=BN_CTX_new();
    BIGNUM* q=BN_new();
    Context(){ require(group&&ctx&&q,"context allocation"); require(EC_GROUP_get_order(group,q,ctx)==1,"group order"); }
    ~Context(){BN_clear_free(q); BN_CTX_free(ctx); EC_GROUP_free(group);}
};
static Context& context(){static thread_local Context c;return c;}
struct F {
    std::array<unsigned char,32> b{};
    F()=default;
    explicit F(std::uint64_t n){ for(int j=31;j>=0 && n;--j){b[j]=n&255;n>>=8;} }
    static F from_bn(const BIGNUM* n){F f;require(BN_bn2binpad(n,f.b.data(),32)==32,"scalar encode");return f;}
    static F parse(const unsigned char* p){F f;std::copy(p,p+32,f.b.begin());auto& c=context();BN_CTX_start(c.ctx);auto n=BN_CTX_get(c.ctx);BN_bin2bn(p,32,n);bool good=BN_cmp(n,c.q)<0;BN_CTX_end(c.ctx);require(good,"noncanonical scalar");return f;}
    static F reduce(const unsigned char* p,std::size_t n){auto& c=context();BN_CTX_start(c.ctx);auto a=BN_CTX_get(c.ctx);auto z=BN_CTX_get(c.ctx);BN_bin2bn(p,n,a);require(BN_nnmod(z,a,c.q,c.ctx)==1,"field reduction");F f=from_bn(z);BN_CTX_end(c.ctx);return f;}
    static F random(bool nonzero=false){auto& c=context();BN_CTX_start(c.ctx);auto a=BN_CTX_get(c.ctx);do{require(BN_priv_rand_range(a,c.q)==1,"scalar RNG");}while(nonzero&&BN_is_zero(a));F f=from_bn(a);BN_CTX_end(c.ctx);return f;}
    bool zero()const{return std::all_of(b.begin(),b.end(),[](auto a){return a==0;});}
    bool bit(int j)const{return (b[31-j/8]>>(j%8))&1;}
    bool operator==(const F& o)const{return b==o.b;}
    bool operator!=(const F& o)const{return !(*this==o);}
    F inv()const{require(!zero(),"zero inverse");auto& c=context();BN_CTX_start(c.ctx);auto a=BN_CTX_get(c.ctx);auto z=BN_CTX_get(c.ctx);BN_bin2bn(b.data(),32,a);require(BN_mod_inverse(z,a,c.q,c.ctx)!=nullptr,"inverse");F f=from_bn(z);BN_CTX_end(c.ctx);return f;}
};
static F op(const F&a,const F&b,int mode){auto& c=context();BN_CTX_start(c.ctx);auto x=BN_CTX_get(c.ctx);auto y=BN_CTX_get(c.ctx);auto z=BN_CTX_get(c.ctx);BN_bin2bn(a.b.data(),32,x);BN_bin2bn(b.b.data(),32,y);int ok=mode==0?BN_mod_add(z,x,y,c.q,c.ctx):mode==1?BN_mod_sub(z,x,y,c.q,c.ctx):BN_mod_mul(z,x,y,c.q,c.ctx);require(ok==1,"field operation");F f=F::from_bn(z);BN_CTX_end(c.ctx);return f;}
static F operator+(const F&a,const F&b){return op(a,b,0);}static F operator-(const F&a,const F&b){return op(a,b,1);}static F operator*(const F&a,const F&b){return op(a,b,2);}
static F hash_scalar(const Bytes& input){unsigned char digest[64];SHA512(input.data(),input.size(),digest);return F::reduce(digest,64);}
static F h0(const Bytes& input){Bytes d={'C','X','-','H','0',0};d.insert(d.end(),input.begin(),input.end());return hash_scalar(d);}
struct P {
    Bytes b{0};
    static P encode(const EC_POINT* p){auto& c=context();P o;auto n=EC_POINT_point2oct(c.group,p,POINT_CONVERSION_COMPRESSED,nullptr,0,c.ctx);require(n==1||n==33,"point encoding length");o.b.resize(n);require(EC_POINT_point2oct(c.group,p,POINT_CONVERSION_COMPRESSED,o.b.data(),n,c.ctx)==n,"point encode");return o;}
    EC_POINT* decode()const{auto& c=context();require(b.size()==1||b.size()==33,"point length");auto p=EC_POINT_new(c.group);if(!p||EC_POINT_oct2point(c.group,p,b.data(),b.size(),c.ctx)!=1||EC_POINT_is_on_curve(c.group,p,c.ctx)!=1){EC_POINT_free(p);throw std::runtime_error("invalid curve point");}return p;}
    static P parse(const Bytes& v){P p;p.b=v;auto q=p.decode();P canonical=encode(q);EC_POINT_free(q);require(canonical.b==v,"noncanonical point");return p;}
    static P base(const F& f){auto& c=context();BN_CTX_start(c.ctx);auto a=BN_CTX_get(c.ctx);BN_bin2bn(f.b.data(),32,a);auto p=EC_POINT_new(c.group);require(EC_POINT_mul(c.group,p,a,nullptr,nullptr,c.ctx)==1,"base scalar multiplication");P o=encode(p);EC_POINT_free(p);BN_CTX_end(c.ctx);return o;}
    P mul(const F& f)const{auto& c=context();auto p=decode();BN_CTX_start(c.ctx);auto a=BN_CTX_get(c.ctx);BN_bin2bn(f.b.data(),32,a);require(EC_POINT_mul(c.group,p,nullptr,p,a,c.ctx)==1,"point scalar multiplication");P o=encode(p);EC_POINT_free(p);BN_CTX_end(c.ctx);return o;}
    P operator+(const P& other)const{auto& c=context();auto p=decode();auto q=other.decode();require(EC_POINT_add(c.group,p,p,q,c.ctx)==1,"point add");P o=encode(p);EC_POINT_free(p);EC_POINT_free(q);return o;}
    P neg()const{auto& c=context();auto p=decode();require(EC_POINT_invert(c.group,p,c.ctx)==1,"point inverse");P o=encode(p);EC_POINT_free(p);return o;}
    bool operator==(const P&o)const{return b==o.b;}
};
struct Wire {
    std::uint64_t bytes=0;
    F scalar(const F& x){bytes+=32;return F::parse(x.b.data());}
    P point(const P& p){bytes+=p.b.size();return P::parse(p.b);}
    std::array<unsigned char,32> seed(){std::array<unsigned char,32>s;require(RAND_priv_bytes(s.data(),s.size())==1,"challenge RNG");bytes+=s.size();return s;}
};
static F coefficient(const std::array<unsigned char,32>& seed,std::uint64_t i){Bytes b(seed.begin(),seed.end());for(int j=0;j<8;++j)b.push_back((i>>(8*j))&255);return hash_scalar(b);}
struct AuthP {F x,w;};
struct AuthV {F v;};
struct Vole {std::vector<AuthP> p;std::vector<AuthV> v;};
static F expand_seed(const osuCrypto::block& seed){unsigned char digest[64];SHA512(reinterpret_cast<const unsigned char*>(&seed),16,digest);return F::reduce(digest,64);}

// Chosen-input prime-field VOLE from malicious-receiver-secure random OT.
// m0=H(s0), correction=m0+key*2^j-H(s1). Sum chosen messages yields
// client w=-sum(m_choice), server v=-sum(m0), hence v=w+key*x.
// Each call runs real base OTs; no setBaseOts from locally paired fake seeds.
static void make_corrections(const std::array<osuCrypto::block,2>* sent,std::size_t count,const std::array<F,256>& delta2,unsigned char* corrections,AuthV* out){
    #pragma omp parallel for num_threads(parallel_threads(count,thread_limit)) schedule(static)
    for(std::size_t i=0;i<count;++i){F sum;for(int j=0;j<256;++j){auto a=expand_seed(sent[i*256+j][0]);auto b=expand_seed(sent[i*256+j][1]);sum=sum+a;auto correction=a+delta2[j]-b;std::copy(correction.b.begin(),correction.b.end(),corrections+(i*256+j)*32);}out[i].v=F()-sum;}
}
static void apply_corrections(const osuCrypto::block* got,const osuCrypto::BitVector& choices,std::size_t count,const unsigned char* received,const F* values,AuthP* out){
    #pragma omp parallel for num_threads(parallel_threads(count,thread_limit)) schedule(static)
    for(std::size_t i=0;i<count;++i){F sum;for(int j=0;j<256;++j){auto m=expand_seed(got[i*256+j]);if(choices[i*256+j])m=m+F::parse(received+(i*256+j)*32);sum=sum+m;}out[i]={values[i],F()-sum};}
}
static Vole real_vole(const F& key,const std::vector<F>& values,Stats& stats){
    using namespace osuCrypto;
    namespace cp=coproto;
    const auto started=Clock::now();
    Vole out;out.p.resize(values.size());out.v.resize(values.size());
    KosOtExtSender sender;KosOtExtReceiver receiver;
    sender.mIsMalicious=true;receiver.mIsMalicious=true;
    auto socks=cp::LocalAsyncSocket::makePair();
    unsigned char seed0[16],seed1[16];require(RAND_priv_bytes(seed0,16)==1&&RAND_priv_bytes(seed1,16)==1,"OT seeds");
    block b0,b1;std::memcpy(&b0,seed0,16);std::memcpy(&b1,seed1,16);PRNG prng0(b0),prng1(b1);
    auto bs=Clock::now();
    std::exception_ptr err0,err1;
    std::thread t0([&]{try{macoro::sync_wait(sender.genBaseOts(prng0,socks[0]));}catch(...){err0=std::current_exception();}});
    std::thread t1([&]{try{macoro::sync_wait(receiver.genBaseOts(prng1,socks[1]));}catch(...){err1=std::current_exception();}});
    t0.join();t1.join();if(err0)std::rethrow_exception(err0);if(err1)std::rethrow_exception(err1);
    stats.base_ot_ms+=ms(bs);stats.base_ot_bytes+=socks[0].bytesReceived()+socks[1].bytesReceived();
    std::array<F,256> delta2;delta2[0]=key;for(int j=1;j<256;++j)delta2[j]=delta2[j-1]+delta2[j-1];
    constexpr std::size_t batch=256;
    for(std::size_t start=0;start<values.size();start+=batch){
        auto count=std::min(batch,values.size()-start);auto ots=count*256;
        AlignedUnVector<std::array<block,2>> sent(ots);AlignedUnVector<block> got(ots);BitVector choices(ots);
        for(std::size_t i=0;i<count;++i)for(int j=0;j<256;++j)choices[i*256+j]=values[start+i].bit(j);
        std::vector<unsigned char> corrections(ots*32),received(ots*32);
        auto send_task=[&]() -> macoro::task<void>{
            co_await sender.send(sent,prng0,socks[0]);
            make_corrections(sent.data(),count,delta2,corrections.data(),out.v.data()+start);
            co_await socks[0].send(coproto::span<unsigned char>(corrections.data(),corrections.size()));
        };
        auto recv_task=[&]() -> macoro::task<void>{
            co_await receiver.receive(choices,got,prng1,socks[1]);
            co_await socks[1].recv(coproto::span<unsigned char>(received.data(),received.size()));
            apply_corrections(got.data(),choices,count,received.data(),values.data()+start,out.p.data()+start);
        };
        err0=nullptr;err1=nullptr;
        std::thread s([&]{try{macoro::sync_wait(send_task());}catch(...){err0=std::current_exception();}});
        std::thread r([&]{try{macoro::sync_wait(recv_task());}catch(...){err1=std::current_exception();}});
        s.join();r.join();if(err0)std::rethrow_exception(err0);if(err1)std::rethrow_exception(err1);
    }
    stats.vole_ms+=ms(started);stats.vole_bytes+=socks[0].bytesReceived()+socks[1].bytesReceived();stats.correlations+=values.size();
    return out;
}
static void commit(AuthP& p,AuthV& v,const F& x,const F& delta,Wire& wire){auto correction=wire.scalar(x-p.x);p.x=x;v.v=v.v+delta*correction;}
static F open(const AuthP& p,const AuthV& v,const F& delta,Wire& wire){auto x=wire.scalar(p.x);auto w=wire.scalar(p.w);require(v.v==w+delta*x,"MAC opening rejected");return x;}
static P sum_points(const std::vector<P>& points,const std::vector<F>& scalars){
    require(points.size()==scalars.size(),"MSM size");
    int threads=parallel_threads(points.size(),thread_limit);std::vector<P> partial(threads);
    #pragma omp parallel for num_threads(threads) schedule(static)
    for(int t=0;t<threads;++t)for(std::size_t i=points.size()*t/threads;i<points.size()*(t+1)/threads;++i)partial[t]=partial[t]+points[i].mul(scalars[i]);
    P sum;for(auto& p:partial)sum=sum+p;return sum;
}

#ifdef CX_TESTING
#define CX_TEST(condition) (condition)
Result shuffled_encoding_test(const std::vector<Bytes>& inputs,const BIGNUM* session_scalar,const std::string& tamper,bool no_rerand,const Bytes& long_term_key){
#else
#define CX_TEST(condition) false
Result shuffled_encoding(const std::vector<Bytes>& inputs,const BIGNUM* session_scalar,const Bytes& long_term_key){
#endif
    require(!inputs.empty(),"empty client vector");
    const std::size_t n=inputs.size();Result result;Wire off,on;Stats& stats=result.stats;
    require(long_term_key.empty()||long_term_key.size()==32,"long-term key length");
    auto offline_start=Clock::now();F k=long_term_key.empty()?F::random(true):F::parse(long_term_key.data()),delta=F::random(true),rs=F::from_bn(session_scalar);require(!k.zero()&&!rs.zero(),"zero session exponent or key");
    result.server_key=Bytes(k.b.begin(),k.b.end());
    // Layout: r[0..n] (r[n] is one-time aVOLE mask), rho[n], kprime[1],
    // t[0..n], x[n], and one one-time polynomial masking correlation.
    auto r_idx=std::size_t(0),rho_idx=n+1,kp_idx=2*n+1,t_idx=2*n+2,x_idx=3*n+3,mask_idx=4*n+3;
    std::vector<F> random_values(4*n+4);for(auto& x:random_values)x=F::random(true);
    if(CX_TEST(tamper=="zero_r"))random_values[0]=F();
    auto before=stats.vole_bytes;auto elapsed=stats.vole_ms;Vole mac=real_vole(delta,random_values,stats);stats.mac_vole_bytes=stats.vole_bytes-before;stats.mac_vole_ms=stats.vole_ms-elapsed;
    std::vector<F> r_values(n+1);for(std::size_t i=0;i<=n;++i)r_values[i]=mac.p[r_idx+i].x;
    if(CX_TEST(tamper=="avole_r"))r_values[0]=r_values[0]+F(1);
    before=stats.vole_bytes;elapsed=stats.vole_ms;Vole keyed=real_vole(k,r_values,stats);stats.key_vole_bytes=stats.vole_bytes-before;stats.key_vole_ms=stats.vole_ms-elapsed;
    // keyed.v=keyed.w+k*r. Hence t=-keyed.w, u=keyed.v.
    for(std::size_t i=0;i<=n;++i)commit(mac.p[t_idx+i],mac.v[t_idx+i],F()-keyed.p[i].w,delta,off);
    // aVOLE consistency, Fig.10 specialized to honest verifier: masked random
    // linear openings of already-committed r and t; verifier checks t+u=k*r.
    auto achallenge=off.seed();AuthP ar=mac.p[r_idx+n],at=mac.p[t_idx+n];AuthV vr=mac.v[r_idx+n],vt=mac.v[t_idx+n];F u=keyed.v[n].v;
    for(std::size_t i=0;i<n;++i){auto chi=coefficient(achallenge,i);ar.x=ar.x+chi*mac.p[r_idx+i].x;ar.w=ar.w+chi*mac.p[r_idx+i].w;vr.v=vr.v+chi*mac.v[r_idx+i].v;at.x=at.x+chi*mac.p[t_idx+i].x;at.w=at.w+chi*mac.p[t_idx+i].w;vt.v=vt.v+chi*mac.v[t_idx+i].v;u=u+chi*keyed.v[i].v;}
    if(CX_TEST(tamper=="mac"))at.w=at.w+F(1);
    auto r_open=open(ar,vr,delta,off),t_open=open(at,vt,delta,off);require(t_open+u==k*r_open,"authenticated VOLE consistency rejected");
    auto prep=Clock::now();F sk=F::random(true);P pk=off.point(P::base(sk));
    std::vector<P>A(n),B(n),rerandA(n),rerandB(n);
    #pragma omp parallel for num_threads(parallel_threads(n,thread_limit)) schedule(static)
    for(std::size_t i=0;i<n;++i){A[i]=P::base(mac.p[rho_idx+i].x);B[i]=pk.mul(mac.p[rho_idx+i].x)+P::base(mac.p[r_idx+i].x);if(CX_TEST(i==0&&tamper=="cipher"))B[i]=B[i]+P::base(F(1));auto eta=CX_TEST(no_rerand)?F():F::random();rerandA[i]=P::base(eta);rerandB[i]=pk.mul(eta);}
    if(CX_TEST(tamper=="invalid_point"))A[0].b={255};
    for(std::size_t i=0;i<n;++i){A[i]=off.point(A[i]);B[i]=off.point(B[i]);}
    stats.prepare_ms=ms(prep);
    // Batched VOLE-ZK-G for A=g^rho and B=pk^rho*g^r, Fig.12.
    auto proof=Clock::now();auto abseed=off.seed();F g_w,pk_w,g_v,pk_v;std::vector<P> targets;std::vector<F> coeffs;
    for(std::size_t i=0;i<n;++i){auto a=coefficient(abseed,2*i),b=coefficient(abseed,2*i+1);g_w=g_w+a*mac.p[rho_idx+i].w+b*mac.p[r_idx+i].w;pk_w=pk_w+b*mac.p[rho_idx+i].w;g_v=g_v+a*mac.v[rho_idx+i].v+b*mac.v[r_idx+i].v;pk_v=pk_v+b*mac.v[rho_idx+i].v;targets.push_back(A[i]);targets.push_back(B[i]);coeffs.push_back(a);coeffs.push_back(b);}
    P abW=off.point(P::base(g_w)+pk.mul(pk_w));require(abW==P::base(g_v)+pk.mul(pk_v)+sum_points(targets,coeffs).mul(delta).neg(),"ciphertext group proof rejected");
    stats.proof_off_ms=ms(proof);stats.offline_ms=ms(offline_start);
    auto online_start=Clock::now();std::vector<F> x(n),e(n);std::vector<P>D(n);
    for(std::size_t i=0;i<n;++i){x[i]=h0(inputs[i]);commit(mac.p[x_idx+i],mac.v[x_idx+i],x[i],delta,on);e[i]=mac.p[r_idx+i].x*x[i]+mac.p[t_idx+i].x;if(CX_TEST(i==0&&tamper=="e"))e[i]=e[i]+F(1);e[i]=on.scalar(e[i]);auto denominator=mac.p[kp_idx].x+x[i];require(!denominator.zero(),"zero tag denominator");D[i]=P::base(denominator.inv());if(CX_TEST(i==0&&tamper=="tag"))D[i]=D[i]+P::base(F(1));D[i]=on.point(D[i]);}
    proof=Clock::now();
    // Degree-2 VOLE-ZK, Fig.11, for r_i*x_i+t_i-e_i=0.
    // rho_x(T)=w_x+T*x. Homogenize linear/public terms to degree 2.
    // Mask the low coefficients with one fresh degree-1 VOLE correlation.
    auto mseed=on.seed();F c0=mac.p[mask_idx].w,c1=mac.p[mask_idx].x,expected=mac.v[mask_idx].v;
    for(std::size_t i=0;i<n;++i){auto chi=coefficient(mseed,i);const auto&r=mac.p[r_idx+i];const auto&xi=mac.p[x_idx+i];c0=c0+chi*(r.w*xi.w);c1=c1+chi*(r.x*xi.w+xi.x*r.w+mac.p[t_idx+i].w);expected=expected+chi*(mac.v[r_idx+i].v*mac.v[x_idx+i].v+delta*mac.v[t_idx+i].v-e[i]*delta*delta);}
    c0=on.scalar(c0);c1=on.scalar(c1);require(c0+delta*c1==expected,"quadratic VOLE-ZK rejected");
    auto dseed=on.seed();F sum_chi;std::vector<F> w_coeff(n),v_coeff(n);
    for(std::size_t i=0;i<n;++i){auto chi=coefficient(dseed,i);sum_chi=sum_chi+chi;w_coeff[i]=chi*(mac.p[kp_idx].w+mac.p[x_idx+i].w);v_coeff[i]=chi*(mac.v[kp_idx].v+mac.v[x_idx+i].v);}
    P dW=on.point(sum_points(D,w_coeff));require(dW==sum_points(D,v_coeff)+P::base(delta*sum_chi).neg(),"deduplication tag proof rejected");
    stats.proof_on_ms=ms(proof);
    std::set<Bytes> distinct;for(const auto& d:D)require(distinct.insert(d.b).second,"duplicate inputs rejected");
    auto eval=Clock::now();std::vector<F> gamma(n);std::vector<P> Aout(n),Bout(n);
    for(std::size_t i=0;i<n;++i){gamma[i]=e[i]+keyed.v[i].v;require(!gamma[i].zero(),"zero gamma rejected");}
    #pragma omp parallel for num_threads(parallel_threads(n,thread_limit)) schedule(static)
    for(std::size_t i=0;i<n;++i){auto power=rs*gamma[i].inv();Aout[i]=A[i].mul(power)+rerandA[i];Bout[i]=B[i].mul(power)+rerandB[i];}
    std::vector<std::size_t> permutation(n);std::iota(permutation.begin(),permutation.end(),0);
    // Unbiased Fisher-Yates using private random integers and rejection.
    for(std::size_t j=n;j>1;--j){std::uint64_t a,limit=UINT64_MAX-UINT64_MAX%j;do{require(RAND_priv_bytes(reinterpret_cast<unsigned char*>(&a),sizeof(a))==1,"shuffle RNG");}while(a>=limit);std::swap(permutation[j-1],permutation[a%j]);}
    std::vector<P> receivedA(n),receivedB(n);for(std::size_t j=0;j<n;++j){receivedA[j]=on.point(Aout[permutation[j]]);receivedB[j]=on.point(Bout[permutation[j]]);}
    stats.server_eval_ms=ms(eval);auto decrypt=Clock::now();result.points.resize(n);std::vector<P>Z(n);
    #pragma omp parallel for num_threads(parallel_threads(n,thread_limit)) schedule(static)
    for(std::size_t j=0;j<n;++j){Z[j]=receivedB[j]+receivedA[j].mul(sk).neg();result.points[j]=Z[j].b;}
    stats.decrypt_ms=ms(decrypt);stats.online_ms=ms(online_start);stats.offline_bytes=stats.vole_bytes+off.bytes;stats.online_bytes=on.bytes;
    if(CX_TEST(no_rerand)){for(std::size_t i=0;i<n;++i)for(std::size_t j=0;j<n;++j)if(receivedA[j]==Z[j].mul(mac.p[rho_idx+i].x*mac.p[r_idx+i].x.inv()))++result.no_rerand_links;}
    return result;
}
std::vector<Bytes> encode_database(const std::vector<Bytes>& inputs,const Bytes& key,const BIGNUM* session_scalar,int threads,std::vector<Bytes>* private_scalars){
    require(key.size()==32,"server key length");F k=F::parse(key.data()),rs=F::from_bn(session_scalar);std::vector<Bytes> out(inputs.size());std::vector<F> inverses(inputs.size());
    // Batch inversion; cold run includes hashing, prefix products and inverse.
    std::vector<F> prefix(inputs.size()+1);prefix[0]=F(1);for(std::size_t i=0;i<inputs.size();++i){inverses[i]=k+h0(inputs[i]);require(!inverses[i].zero(),"zero database denominator");prefix[i+1]=prefix[i]*inverses[i];}
    F inverse=prefix.back().inv();for(std::size_t i=inputs.size();i-->0;){auto d=inverses[i];inverses[i]=inverse*prefix[i]*rs;inverse=inverse*d;}
    #pragma omp parallel for num_threads(threads) schedule(static)
    for(std::size_t i=0;i<inputs.size();++i)out[i]=P::base(inverses[i]).b;
    if(private_scalars){private_scalars->resize(inverses.size());for(size_t i=0;i<inverses.size();++i)(*private_scalars)[i]=Bytes(inverses[i].b.begin(),inverses[i].b.end());}
    return out;
}
void print_stats(const Stats&s,std::size_t n){std::cout<<std::setprecision(9)<<"CX_PROOF_JSON {\"n\":"<<n<<",\"backend\":\"KOS_bit_OT_P256_prime_VOLE_unified_threads\",\"offline_ms\":"<<s.offline_ms<<",\"online_ms\":"<<s.online_ms<<",\"vole_ms\":"<<s.vole_ms<<",\"mac_vole_ms\":"<<s.mac_vole_ms<<",\"key_vole_ms\":"<<s.key_vole_ms<<",\"base_ot_ms\":"<<s.base_ot_ms<<",\"prepare_ms\":"<<s.prepare_ms<<",\"proof_off_ms\":"<<s.proof_off_ms<<",\"proof_on_ms\":"<<s.proof_on_ms<<",\"server_eval_ms\":"<<s.server_eval_ms<<",\"decrypt_ms\":"<<s.decrypt_ms<<",\"offline_bytes\":"<<s.offline_bytes<<",\"online_bytes\":"<<s.online_bytes<<",\"vole_bytes\":"<<s.vole_bytes<<",\"mac_vole_bytes\":"<<s.mac_vole_bytes<<",\"key_vole_bytes\":"<<s.key_vole_bytes<<",\"base_ot_bytes\":"<<s.base_ot_bytes<<",\"correlations\":"<<s.correlations<<"}"<<std::endl;}
#ifdef CX_TESTING
bool old_relation_attack(){F rs=F::random(true);P u=P::base(F::random(true)),v=P::base(F::random(true));std::vector<P> out={v.mul(F(3)*rs),u.mul(rs),v.mul(rs),u.mul(F(2)*rs)};return out[1].mul(F(2))==out[3]&&out[2].mul(F(3))==out[0];}
#endif
}
