#ifndef LPSI_CONFIG_H
#define LPSI_CONFIG_H

#include <cstddef>
#include <cstdint>
#include <string>

// ========================================
// Payable LPSI protocol parameters.
// ========================================
class PpsiParm {
    
public:
    PpsiParm();
    ~PpsiParm();

    uint64_t poly_degree = 8192; // Polynomial degree (PIR parameter).
};


namespace LPSIConfig {
    // ===== Hash bucket configuration =====
    const std::string input_data_main_cuckoo = "../data/input_data_main_cuckoo.txt";
    
    // Main bucket count multiplier relative to the receiver's input size.
    // Recommended: 2.5-3.0. Larger values improve cuckoo insertion success at a higher communication cost.
    constexpr double MAIN_BUCKET_FACTOR = 1.5;
    constexpr double SUB_BUCKET_FACTOR = 0.6; // Sub-bucket capacity multiplier relative to the largest main bucket.
    // Maximum retry count. Two-way cuckoo hashing with nh=2 converges more slowly and needs more retries.
    constexpr size_t MAX_RETRY = 5000;

    // Number of hash functions (candidate positions for cuckoo hashing).
    constexpr int OUTER_NUM_HASH_FUNCTIONS = 3;
    
    // Number of sub-buckets in each main bucket for the second hashing level.
    // The number of inner cuckoo hash functions should equal the number of sub-buckets.
    constexpr int NUM_SUB_BUCKETS = 3;
    
    // Sub-bucket capacity (number of elements per sub-bucket).
    // Capacity is now calculated dynamically from the input size rather than this constant.
    constexpr size_t SUB_BUCKET_CAPACITY = 20;  // Retained as the minimum capacity.
    
    // Bucket key size.
    constexpr size_t BUCKET_KEY_SIZE_BYTES = 32;
    
    // ===== Hash function seeds =====
    
    // Seeds for distinct hash function instances.
    constexpr uint32_t HASH_SEEDS[] = {
        0x12345678, // Hash function 0.
        0x9ABCDEF0, // Hash function 1.
        0xFEDCBA98, // Hash function 2.
        0x13579BDF, // Hash function 3.
        0x2468ACE1, // Hash function 4.
        0x0F1E2D3C, // Hash function 5.
        0x89ABCDEF, // Hash function 6.
        0xCAFEBABE, // Hash function 7.
        0xDEADBEEF, // Hash function 8.
        0xA5A5A5A5  // Hash function 9.
    };
    
    // ===== PIR configuration =====
    
    // PIR database entry size in bytes.
    // x_prime + masked_value
    
    inline size_t PIR_PAYLOAD_SIZE = 64;
    
    // ===== Cryptographic parameters =====
    
    // Random key size in bytes.
    constexpr size_t BUCKET_KEY_SIZE = 32;
    
    constexpr int DH_PRIME_BITS = 2048;
}

#endif // LPSI_CONFIG_H
