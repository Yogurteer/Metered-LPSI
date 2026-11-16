#include "cx_delivery.h"
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <coproto/Socket/LocalAsyncSock.h>
#include <chrono>
#include <mutex>
#include <stdexcept>
#include <string>
#include <atomic>
#include <algorithm>
extern "C" int cx_p256_h2g(const unsigned char*,size_t,const unsigned char*,size_t,unsigned char*);
namespace cxdelivery {
using Clock=std::chrono::steady_clock;
static void check(bool ok,const char* message){if(!ok)throw std::runtime_error(message);}
static double elapsed(Clock::time_point start){return std::chrono::duration<double,std::milli>(Clock::now()-start).count();}
static void u64(Bytes& b,std::uint64_t n){for(int i=7;i>=0;--i)b.push_back((n>>(8*i))&255);}
static std::uint64_t read64(const Bytes& b,size_t pos){check(pos+8<=b.size(),"short integer");std::uint64_t n=0;for(size_t i=pos;i<pos+8;++i)n=(n<<8)|b[i];return n;}
static Bytes input(const Bytes& ctx,size_t j){Bytes out={'M','L','P','S','I','-','D','e','l','i','v','e','r','y','-','v','1',0};out.insert(out.end(),ctx.begin(),ctx.end());u64(out,j);return out;}
struct Group {
    EC_GROUP* g=EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* c=BN_CTX_new(); BIGNUM* q=BN_new();
    Group(){check(g&&c&&q&&EC_GROUP_get_order(g,q,c)==1,"group allocation");}
    ~Group(){BN_clear_free(q);BN_CTX_free(c);EC_GROUP_free(g);}
    BIGNUM* random(){auto r=BN_new();check(r,"scalar allocation");do{check(BN_priv_rand_range(r,q)==1,"scalar randomness");}while(BN_is_zero(r));BN_set_flags(r,BN_FLG_CONSTTIME);return r;}
    Bytes scalar(const BIGNUM* r){Bytes b(32);check(BN_bn2binpad(r,b.data(),32)==32,"scalar encode");return b;}
    BIGNUM* scalar(const Bytes& b){check(b.size()==32,"scalar length");auto r=BN_bin2bn(b.data(),32,nullptr);check(r&&!BN_is_zero(r)&&BN_cmp(r,q)<0,"scalar range");BN_set_flags(r,BN_FLG_CONSTTIME);return r;}
    Bytes encode(const EC_POINT* pt){Bytes b(33);check(EC_POINT_point2oct(g,pt,POINT_CONVERSION_COMPRESSED,b.data(),b.size(),c)==33,"point encode");return b;}
    EC_POINT* decode(const Bytes& b){check(b.size()==33&&(b[0]==2||b[0]==3),"point encoding");auto pt=EC_POINT_new(g);if(!pt||EC_POINT_oct2point(g,pt,b.data(),b.size(),c)!=1||EC_POINT_is_at_infinity(g,pt)||EC_POINT_is_on_curve(g,pt,c)!=1){EC_POINT_free(pt);throw std::runtime_error("invalid point");}return pt;}
    EC_POINT* hash(const Bytes& in){
        const std::string prefix="HashToGroup-OPRFV1-";
        Bytes dst(prefix.begin(),prefix.end());dst.push_back(0);
        const std::string suffix="-P256-SHA256";dst.insert(dst.end(),suffix.begin(),suffix.end());
        Bytes out(33);check(cx_p256_h2g(in.data(),in.size(),dst.data(),dst.size(),out.data())==0,"RFC9380 hash to group");return decode(out);
    }
    Bytes finish(const Bytes& in,const EC_POINT* pt){check(in.size()<=65535,"OPRF input too long");auto z=encode(pt);Bytes b; b.push_back(in.size()>>8);b.push_back(in.size()&255);b.insert(b.end(),in.begin(),in.end());b.push_back(0);b.push_back(z.size());b.insert(b.end(),z.begin(),z.end());const std::string s="Finalize";b.insert(b.end(),s.begin(),s.end());Bytes out(32);SHA256(b.data(),b.size(),out.data());return out;}
};
// Catch exceptions inside OpenMP regions; no process termination may hide failure.
template<class F>static void parallel(size_t n,int threads,F fn){std::atomic<bool> failed=false;
    #pragma omp parallel num_threads(threads)
    {Group g;
        #pragma omp for schedule(static)
        for(size_t i=0;i<n;++i){try{fn(g,i);}catch(...){failed=true;}}
    }check(!failed,"Delivery parallel operation failed");
}
struct Server::Impl { Bytes key,ctx; size_t buckets=0,paid=0; enum State{New,Prepared,Authorized,Consumed,Aborted}state=New;mutable std::mutex lock;double prep_ms=0;~Impl(){if(!key.empty())OPENSSL_cleanse(key.data(),key.size());}};
Server::Server():p(std::make_unique<Impl>()){} Server::~Server()=default;
std::vector<Bytes> Server::prepare(size_t b,int threads){std::lock_guard<std::mutex> guard(p->lock);check(p->state==Impl::New||p->state==Impl::Prepared,"Delivery reset forbidden");check(b>0&&threads>0,"Delivery preparation parameters");auto t=Clock::now();Group g;auto k=g.random();if(!p->key.empty())OPENSSL_cleanse(p->key.data(),p->key.size());p->key=g.scalar(k);BN_clear_free(k);p->ctx.assign(32,0);check(RAND_bytes(p->ctx.data(),32)==1,"context randomness");u64(p->ctx,b);p->buckets=b;std::vector<Bytes> keys(b);
    try{parallel(b,threads,[&](Group& local,size_t j){auto h=local.hash(input(p->ctx,j));auto key=local.scalar(p->key);check(EC_POINT_mul(local.g,h,nullptr,h,key,local.c)==1,"server key derivation");keys[j]=local.finish(input(p->ctx,j),h);BN_clear_free(key);EC_POINT_free(h);});p->state=Impl::Prepared;p->prep_ms+=elapsed(t);}catch(...){p->state=Impl::Aborted;throw;}return keys;
}
Bytes Server::context() const {std::lock_guard<std::mutex> guard(p->lock);check(p->state!=Impl::New&&p->state!=Impl::Aborted,"context unavailable");return p->ctx;}
void Server::authorize(size_t tau){std::lock_guard<std::mutex> guard(p->lock);check(p->state==Impl::Prepared,"authorization state");if(tau>p->buckets){p->state=Impl::Aborted;throw std::runtime_error("payment budget too large");}p->paid=tau;p->state=Impl::Authorized;}
std::vector<Bytes> Server::evaluate(const Request& req,int threads){std::lock_guard<std::mutex> guard(p->lock);check(p->state==Impl::Authorized,"Delivery replay or missing authorization");p->state=Impl::Aborted;check(req.context==p->ctx&&req.points.size()==p->paid,"Delivery context or budget mismatch");check(threads>0,"thread count");std::vector<Bytes> out(req.points.size());parallel(out.size(),threads,[&](Group& local,size_t i){auto pt=local.decode(req.points[i]);auto k=local.scalar(p->key);check(EC_POINT_mul(local.g,pt,nullptr,pt,k,local.c)==1,"server evaluation");out[i]=local.encode(pt);EC_POINT_free(pt);BN_clear_free(k);});p->state=Impl::Consumed;return out;}
double Server::preparation_ms() const {std::lock_guard<std::mutex> guard(p->lock);return p->prep_ms;}
Request blind(const Bytes& ctx,const std::vector<size_t>& indices,ClientState& st,int threads){check(ctx.size()==40&&threads>0,"client context");st.context=ctx;st.inputs.resize(indices.size());st.inverses.resize(indices.size());Request req{ctx,std::vector<Bytes>(indices.size())};parallel(indices.size(),threads,[&](Group& g,size_t i){check(indices[i]<read64(ctx,32),"bucket index out of range");st.inputs[i]=input(ctx,indices[i]);auto h=g.hash(st.inputs[i]);auto r=g.random();auto inv=BN_mod_inverse(nullptr,r,g.q,g.c);check(inv,"blind inverse");st.inverses[i]=g.scalar(inv);check(EC_POINT_mul(g.g,h,nullptr,h,r,g.c)==1,"client blinding");req.points[i]=g.encode(h);EC_POINT_free(h);BN_clear_free(r);BN_clear_free(inv);});return req;}
std::vector<Bytes> finalize(const ClientState& st,const std::vector<Bytes>& responses,int threads){check(responses.size()==st.inputs.size()&&responses.size()==st.inverses.size(),"response count");std::vector<Bytes> out(responses.size());parallel(out.size(),threads,[&](Group& g,size_t i){auto pt=g.decode(responses[i]);auto inv=g.scalar(st.inverses[i]);check(EC_POINT_mul(g.g,pt,nullptr,pt,inv,g.c)==1,"unblind");out[i]=g.finish(st.inputs[i],pt);EC_POINT_free(pt);BN_clear_free(inv);});return out;}
static Bytes pack(const Request& r){Bytes b=r.context;u64(b,r.points.size());for(const auto& pt:r.points){check(pt.size()==33,"wire point length");b.insert(b.end(),pt.begin(),pt.end());}return b;}
static Request unpack(const Bytes& b){check(b.size()>=48,"short Delivery frame");auto n=read64(b,40);check(n<=(b.size()-48)/33&&b.size()==48+33*n,"Delivery frame size");Request r{Bytes(b.begin(),b.begin()+40),{}};r.points.reserve(n);for(size_t i=0;i<n;++i)r.points.emplace_back(b.begin()+48+33*i,b.begin()+48+33*(i+1));return r;}
static Bytes transfer(coproto::LocalAsyncSocket& from,coproto::LocalAsyncSocket& to,const Bytes& msg){Bytes out(msg.size());auto send=from.send(msg);auto recv=to.recv(out);macoro::sync_wait(macoro::when_all_ready(std::move(send),std::move(recv)));check(out==msg,"transport mismatch");return out;}
std::vector<Bytes> deliver(Server& server,const std::vector<size_t>& indices,int threads,Stats& stats){auto t=Clock::now();auto socks=coproto::LocalAsyncSocket::makePair();auto ctx=transfer(socks[0],socks[1],server.context());ClientState st;auto req=blind(ctx,indices,st,threads);auto server_request=unpack(transfer(socks[1],socks[0],pack(req)));server.authorize(indices.size());auto responses=server.evaluate(server_request,threads);auto client_response=unpack(transfer(socks[0],socks[1],pack({ctx,responses})));check(client_response.context==st.context,"response context mismatch");auto keys=finalize(st,client_response.points,threads);stats.online_ms=elapsed(t);stats.wire_bytes=socks[0].bytesReceived()+socks[1].bytesReceived();return keys;}
static Bytes hex(const std::string& s){Bytes b;for(size_t i=0;i<s.size();i+=2)b.push_back(std::stoul(s.substr(i,2),nullptr,16));return b;}
bool rfc9497_vectors(){Group g;auto key=g.scalar(hex("159749d750713afe245d2d39ccfaae8381c53ce92d098a9375ee70739c7ac0bf"));auto r=g.scalar(hex("3338fa65ec36e0290022b48eb562889d89dbfa691d1cde91517fa222ed7ad364"));auto inv=BN_mod_inverse(nullptr,r,g.q,g.c);const std::vector<std::vector<std::string>> vectors={
 {"00","03723a1e5c09b8b9c18d1dcbca29e8007e95f14f4732d9346d490ffc195110368d","030de02ffec47a1fd53efcdd1c6faf5bdc270912b8749e783c7ca75bb412958832","a0b34de5fa4c5b6da07e72af73cc507cceeb48981b97b7285fc375345fe495dd"},
 {"5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a","03cc1df781f1c2240a64d1c297b3f3d16262ef5d4cf102734882675c26231b0838","03a0395fe3828f2476ffcd1f4fe540e5a8489322d398be3c4e5a869db7fcb7c52c","c748ca6dd327f0ce85f4ae3a8cd6d4d5390bbb804c9e12dcf94f853fece3dcce"}};
 bool ok=true;for(auto& v:vectors){auto in=hex(v[0]);auto h=g.hash(in);check(EC_POINT_mul(g.g,h,nullptr,h,r,g.c)==1,"vector blind");ok=ok&&g.encode(h)==hex(v[1]);check(EC_POINT_mul(g.g,h,nullptr,h,key,g.c)==1,"vector evaluate");ok=ok&&g.encode(h)==hex(v[2]);check(EC_POINT_mul(g.g,h,nullptr,h,inv,g.c)==1,"vector unblind");ok=ok&&g.finish(in,h)==hex(v[3]);EC_POINT_free(h);}BN_clear_free(key);BN_clear_free(r);BN_clear_free(inv);return ok;}
}
