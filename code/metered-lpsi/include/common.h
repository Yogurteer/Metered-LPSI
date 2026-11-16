#ifndef COMMON_H
#define COMMON_H

#include <cstddef>
#include <cstdint>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <vector>
#include <cstdint>
#include <omp.h>

#include "config.h"
#include "kuku/kuku.h"

// Type definitions.
using Element = std::vector<unsigned char>;
using ElementVector = std::vector<Element>;

// Measure the total size of an ElementVector in bytes.
inline size_t get_payload_size(const ElementVector& ev) {
    size_t total_bytes = 0;
    
    // Method 1: Sum the element sizes in a simple loop.
    for (const auto& element : ev) {
        // element.size() is the number of unsigned char values, hence the byte count.
        total_bytes += element.size();
    }

    return total_bytes;
}

// All computational stages use the same per-role worker limit (-t).
extern int g_thread_count;
inline int get_thread_count() { return g_thread_count; }

// 1. Compress an arbitrary-length byte sequence into a 128-bit Kuku item_type.
// Method: use Kuku's HashFunction::hash(bytes).
// Compress arbitrary-length bytes into a 128-bit kuku::item_type.
inline kuku::item_type make_item_from_bytes(const std::vector<uint8_t>& bytes)
{
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(bytes.data(), bytes.size(), hash);

    uint64_t high = 0, low = 0;

    // First 8 bytes -> high.
    for (int i = 0; i < 8; i++) {
        high = (high << 8) | hash[i];
    }
    // Last 8 bytes -> low.
    for (int i = 8; i < 16; i++) {
        low = (low << 8) | hash[i];
    }

    return kuku::make_item(high, low);
}

// 2. Hash function instances using Kuku tabulation hashing.
inline size_t instance_hash(const Element& bytes,
                                int hash_idx,
                                size_t bucket_count)
{
    // Step 1: convert bytes → 128-bit item
    kuku::item_type item = make_item_from_bytes(bytes);

    // Step 2: Use a different seed for each hash_idx, converted to item_type for Kuku.
    uint64_t seed_low = 0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(hash_idx + 1);
    uint64_t seed_high = seed_low ^ 0xD1B54A32D192ED03ULL;
    kuku::item_type seed_item = kuku::make_item(seed_low, seed_high);

    // 3. Construct a Kuku LocFunc using the Kuku 2.1 hashing interface.
    kuku::LocFunc loc_func(static_cast<kuku::table_size_type>(bucket_count), seed_item);

    // 4. Call the location function to obtain the bucket index.
    size_t pos = loc_func(item);

    return pos % bucket_count;
}

class MyTimer
{
public:
  MyTimer() { _start = std::chrono::high_resolution_clock::now(); }

  inline double elapsed()
  {
    _end = std::chrono::high_resolution_clock::now();
    return std::chrono::duration_cast<std::chrono::microseconds>(_end - _start)
               .count() /
           1000.0;
  }

  inline void reset() { _start = std::chrono::high_resolution_clock::now(); }
  ~MyTimer(){};

private:
  std::chrono::high_resolution_clock::time_point _start, _end;
};

// Helper: hash to curve using try-and-increment.
// Map arbitrary data to a valid point on the P-256 curve.
inline EC_POINT* map_data_to_point(const EC_GROUP* group, const Element& data, BN_CTX* ctx) {
    EC_POINT* point = EC_POINT_new(group);
    BIGNUM* x_coord = BN_new();
    uint32_t counter = 0;
    unsigned char hash[SHA256_DIGEST_LENGTH];
    
    // Copy the data so a counter can be appended.
    std::vector<uint8_t> buffer = data;
    size_t original_size = buffer.size();
    buffer.resize(original_size + 4); // Reserve 4 bytes for the counter.

    while (true) {
        // buffer = data || counter
        buffer[original_size] = (counter >> 24) & 0xFF;
        buffer[original_size + 1] = (counter >> 16) & 0xFF;
        buffer[original_size + 2] = (counter >> 8) & 0xFF;
        buffer[original_size + 3] = counter & 0xFF;

        SHA256(buffer.data(), buffer.size(), hash);
        BN_bin2bn(hash, SHA256_DIGEST_LENGTH, x_coord);

        // Treat the hash as an X coordinate and recover Y by decompressing the point.
        // The argument 0 selects an even Y coordinate for deterministic output.
        if (EC_POINT_set_compressed_coordinates_GFp(group, point, x_coord, 0, ctx) == 1) {
            break; // A valid point was found.
        }
        counter++;
    }

    BN_free(x_coord);
    return point;
}

#endif // COMMON_H
