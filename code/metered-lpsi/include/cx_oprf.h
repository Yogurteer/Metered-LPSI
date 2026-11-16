#pragma once
#include <array>
#include <cstdint>
#include <string>
#include <vector>
#include <openssl/bn.h>

namespace cx {
void set_thread_limit(int threads);
using Bytes = std::vector<unsigned char>;
struct Stats {
    double offline_ms=0, online_ms=0, vole_ms=0, mac_vole_ms=0, key_vole_ms=0;
    double prepare_ms=0, proof_off_ms=0, proof_on_ms=0, server_eval_ms=0, decrypt_ms=0;
    std::uint64_t offline_bytes=0, online_bytes=0, vole_bytes=0, mac_vole_bytes=0, key_vole_bytes=0;
    std::uint64_t base_ot_bytes=0, correlations=0;
    double base_ot_ms=0;
};
struct Result {
    std::vector<Bytes> points;
    Bytes server_key;
    Stats stats;
    std::size_t no_rerand_links=0;
};
// Measurement harness, with separate prover/verifier state. Actual KOS/base OTs;
// no trusted correlation dealer. Other messages use serialized in-process transport.
#ifdef CX_TESTING
Result shuffled_encoding_test(const std::vector<Bytes>& inputs, const BIGNUM* session_scalar,
                     const std::string& tamper="", bool no_rerand=false,
                     const Bytes& long_term_key={});
#else
Result shuffled_encoding(const std::vector<Bytes>& inputs, const BIGNUM* session_scalar,
                         const Bytes& long_term_key={});
#endif
std::vector<Bytes> encode_database(const std::vector<Bytes>& inputs, const Bytes& key,
                                 const BIGNUM* session_scalar, int threads,
                                 std::vector<Bytes>* private_scalars=nullptr);
void print_stats(const Stats& s, std::size_t n);
#ifdef CX_TESTING
bool old_relation_attack();
#endif
}
