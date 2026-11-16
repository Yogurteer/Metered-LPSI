#pragma once
#include <cstdint>
#include <memory>
#include <vector>
namespace cxdelivery {
using Bytes=std::vector<unsigned char>;
struct Request { Bytes context; std::vector<Bytes> points; };
struct ClientState { Bytes context; std::vector<Bytes> inputs, inverses; };
struct Stats { double online_ms=0; std::uint64_t wire_bytes=0; };
class Server {
    struct Impl; std::unique_ptr<Impl> p;
public:
    Server(); ~Server();
    // A fresh key and context for each preprocessing attempt. No reset after authorization.
    std::vector<Bytes> prepare(std::size_t buckets,int threads);
    Bytes context() const;
    void authorize(std::size_t paid_count);
    std::vector<Bytes> evaluate(const Request& request,int threads);
    double preparation_ms() const;
};
Request blind(const Bytes& context,const std::vector<std::size_t>& indices,ClientState&,int threads);
std::vector<Bytes> finalize(const ClientState&,const std::vector<Bytes>& responses,int threads);
std::vector<Bytes> deliver(Server&,const std::vector<std::size_t>& indices,int threads,Stats&);
bool rfc9497_vectors();
}
