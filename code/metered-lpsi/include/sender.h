#ifndef LPSI_SENDER_H
#define LPSI_SENDER_H

#include <vector>
#include <string>
#include <memory>
#include <array>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <kuku/kuku.h>
#include "common.h"
#include "cx_delivery.h"

// Sender-side bucket data structure.
struct SenderBucketData {
    Element pir_key;         // H_1((H(x_i)^r_s)^{l_j})
    Element masked_value;    // x_i || v_i ⊕ H_2(s_j, (H(x_i)^r_s)^{l_j})
    size_t source_index = static_cast<size_t>(-1);  // Corresponding original input element index.
};

class LPSISender {
#ifdef CX_TESTING
    friend struct BucketTestAccess;
#endif
private:
    // Input data.
    std::vector<std::pair<Element, Element>> input_data;  // (X, V) pairs
    
    // Cryptographic parameters.
    BIGNUM* r_s;              // Sender's random scalar.
    EC_GROUP* group;          // Curve group parameters, replacing prime_p.
    // BN_CTX* bn_ctx; // Removed: threads must use locally created contexts rather than sharing one.
    
    // Intermediate results.
    ElementVector private_encoding_scalars; // Server-only DY exponents, never transmitted.
    ElementVector X_prime;                              // H_1(H(x_i)^r_s)
    ElementVector H_x_rs_bytes;                         // H(x_i)^r_s, used to compute H_2.
    std::vector<Element> bucket_keys;                   // Random decryption key s_j for each main bucket.
    std::vector<BIGNUM*> bucket_oprf_exponents;         // Second-round OPRF exponent l_j for each main bucket.
    
    // Hash bucket data.
    std::vector<std::vector<SenderBucketData>> X_star;  // Main buckets.
    std::vector<std::vector<std::vector<SenderBucketData>>> X_sub_star;  // Sub-buckets: [main][sub][slot].
    
    // PIR database.
    std::vector<SenderBucketData> flattened_database;   // Concatenated database.
    
    // Statistics.
    size_t intersection_size;
    
    // Helper functions.
    // Element hash_H(const Element& input);
    Element hash_H1(const Element& input);
    Element hash_H2(const Element& key, const Element& data);
    Element hash_H2(const Element& key, const Element& data, size_t out_len);
    void xor_with_hash_H2(const Element& key, const Element& data, const Element& input, Element& output);
    Element xor_elements(const Element& a, const Element& b);
    void clear_bucket_oprf_exponents();
    // Convert a point to compressed bytes.
    Element point_to_bytes(const EC_POINT* point, BN_CTX* ctx);
    // Convert bytes to a point.
    EC_POINT* bytes_to_point(const Element& bytes, BN_CTX* ctx);

    // Data structure parameters.
    size_t num_main_b;
    bool bucket_oprf_consumed=false;

    // Item and label byte lengths supplied externally for masked_value encoding and decoding.
    size_t item_byte_ = 16;   // Item (key) length in bytes.
    size_t label_byte_ = 1;   // Label (value) length in bytes.


public:
    cxdelivery::Server cx_delivery;
    LPSISender();
    LPSISender(size_t item_byte, size_t label_byte);
    ~LPSISender();
    
    const auto& cx_input() const { return input_data; }
    void cx_set_encodings(const ElementVector& points, const ElementVector& private_scalars);
    // Set the input data (X, V).
    void set_input(const std::vector<std::pair<Element, Element>>& data);

    // Phase 2: Main hash buckets and sub-buckets.
    void build_hash_buckets(size_t num_main_buckets, int num_hash_funcs);
    void prepare_bucket_bound_entries();
    void build_sub_buckets(size_t sender_data_size, size_t num_main_buckets, int nh);

    // Phase 2.5: Second-round OPRF per bucket.
    ElementVector process_bucket_oprf_step2(const ElementVector& receiver_masked);
    
    // Phase 3: Prepare the PIR database.
    void prepare_pir_database();
    std::vector<Element> get_pir_database_as_bytes(size_t& num_items, size_t& item_size);

    // Retrieve statistics.
    size_t get_intersection_size() const { return intersection_size; }
    void set_intersection_size(size_t size) { intersection_size = size; }
    
    // Retrieve bucket structure information so the receiver can compute PIR indices.
    size_t get_num_main_buckets() const { return num_main_b; }
    std::pair<size_t, size_t> get_sub_bucket_structure() const {
        if (X_sub_star.empty() || X_sub_star[0].empty()) return {0, 0};
        return {X_sub_star[0].size(), X_sub_star[0][0].size()};  // (nh, capacity)
    }
    
    // Debug interface.

    const BIGNUM* get_r_s() const { return r_s; }

};

#endif // LPSI_SENDER_H
