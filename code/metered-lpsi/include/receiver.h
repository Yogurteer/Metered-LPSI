#ifndef LPSI_RECEIVER_H
#define LPSI_RECEIVER_H

#include <vector>
#include <string>
#include <sstream>
#include <memory>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <kuku/kuku.h>
#include "common.h"

// Forward declaration.
struct SenderBucketData;

class LPSIReceiver {
private:
    // Input data.
    ElementVector input_data;  // Y
    
    // Cryptographic parameters.
    BIGNUM* r_c;              // Receiver's random scalar.
    BIGNUM* r_c_inv;          // Multiplicative inverse of r_c.
    EC_GROUP* group;          // ECC group.
    
    // Intermediate results.
    ElementVector Y_prime;                               // H_1(H(y_i*)^r_s)
    ElementVector H_y_rs;                                // H(y_i*)^r_s, used for decryption.
    ElementVector bucket_bound_points;                   // (H(y_i)^r_s)^{l_j}
    ElementVector bucket_bound_tags;                     // H_1((H(y_i)^r_s)^{l_j})
    std::vector<BIGNUM*> bucket_oprf_blind_invs;        // Inverse blinding factors for the second OPRF round.
    std::vector<std::vector<Element>> Y_star;            // Main buckets: [main_idx][0], with one element per cuckoo bucket.
    std::vector<std::vector<std::vector<Element>>> Y_sub_star;  // Sub-buckets: [main][sub][slot].
    
    // Query indices.
    std::vector<std::vector<size_t>> query_indices;      // [query_group][hash_idx] = local_index.
    std::vector<size_t> valid_bucket_indices;            // Main bucket indices corresponding to valid queries.
    std::vector<size_t> element_to_main_bucket;          // [y_idx] = main_bucket_idx, the unique main bucket assigned to each element.
    std::vector<size_t> main_bucket_to_element;          // [main_bucket_idx] = y_idx; INVALID if the bucket is empty.
    std::vector<size_t> hit_sub_bucket_indices;          // Record the matching sub-bucket index among the nh candidates for each hit.
    
    // Sender bucket structure, used for index conversion.
    size_t sender_num_main_buckets;
    size_t sender_nh;
    size_t sender_sub_capacity;
    
    // Final intersection.
    std::vector<std::pair<Element, Element>> intersection;  // (x_i, v_i)
    
    // Item and label byte lengths supplied externally for masked_value decryption.
    size_t item_byte_ = 16;   // Item (key) length in bytes.
    size_t label_byte_ = 1;   // Label (value) length in bytes.

    // Helper functions.
    Element hash_H1(const Element& input);
    Element hash_H2(const Element& key, const Element& data);
    Element hash_H2(const Element& key, const Element& data, size_t out_len);
    Element point_to_bytes(const EC_POINT* point, BN_CTX* ctx);
    EC_POINT* bytes_to_point(const Element& bytes, BN_CTX* ctx);
    Element xor_elements(const Element& a, const Element& b);
    void clear_bucket_oprf_blinds();
    
    // Save data to a file in hexadecimal format.

    
public:
    LPSIReceiver();
    LPSIReceiver(size_t item_byte, size_t label_byte);
    ~LPSIReceiver();

    // PIR results.
    std::vector<Element> pir_results;                    // Ciphertexts returned by PIR.
    std::vector<size_t> hit_element_indices;             // Indices of elements matched by PIR, referring to positions in Y_prime.
    
    const auto& cx_input() const { return input_data; }
    void cx_select_purchases(size_t tau);
    void cx_set_encodings(const ElementVector& points);
    // Set the input data Y.
    void set_input(const ElementVector& data);

    // Phase 2: Main hash buckets and sub-buckets.
    void build_hash_buckets(size_t bucket_count, int num_hash_funcs);
    void build_sub_buckets(size_t sender_data_size, size_t num_main_buckets, int nh);

    // Phase 2.5: Second-round OPRF per bucket.
    ElementVector compute_bucket_bound_oprf_step1();
    void process_bucket_bound_oprf_step3(const ElementVector& sender_output);
    
    // Phase 3: Generate PIR query indices.
    void generate_pir_query_indices(size_t sender_num_main_buckets, 
                                     size_t sender_nh, 
                                     size_t sender_sub_capacity);
    std::vector<uint32_t> get_query_indices_flat() const;
    
    // Phase 4: Process PIR results.
    void process_pir_results(const std::vector<Element>& results);
    
    // Phase 5: Obtain bucket keys.

    
    std::vector<size_t> get_delivery_choices() const;
    
    // Phase 6: Decrypt the intersection.
    void decrypt_intersection(const std::vector<Element>& bucket_keys);
    
    // Retrieve results.
    const std::vector<std::pair<Element, Element>>& get_intersection() const { 
        return intersection; 
    }

    const ElementVector& get_bucket_bound_tags() const { return bucket_bound_tags; }

};

#endif // LPSI_RECEIVER_H
