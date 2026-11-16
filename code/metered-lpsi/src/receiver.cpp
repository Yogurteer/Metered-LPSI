#include "receiver.h"
#include "sender.h"  // Requires the SenderBucketData definition.
#include "config.h"
#include <openssl/sha.h>
#include <cstring>
#include <cmath>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <random>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <numeric>
#include <set>
#include <stdexcept>
#include <omp.h>

// Parameterized constructor.
LPSIReceiver::LPSIReceiver(size_t item_byte, size_t label_byte)
    : item_byte_(item_byte), label_byte_(label_byte) {
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    r_c = BN_new();
    r_c_inv = BN_new();
    BN_rand_range(r_c, order);
    BN_mod_inverse(r_c_inv, r_c, order, ctx);
    BN_free(order);
    BN_CTX_free(ctx);
}

LPSIReceiver::LPSIReceiver() {
    // Initialize P-256.
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    
    r_c = BN_new();
    r_c_inv = BN_new();
    
    // Generate r_c and r_c_inv modulo the group order.
    BN_rand_range(r_c, order);
    BN_mod_inverse(r_c_inv, r_c, order, ctx); // Compute the ECC scalar inverse modulo the group order.
    
    BN_free(order);
    BN_CTX_free(ctx);
}

LPSIReceiver::~LPSIReceiver() {
    clear_bucket_oprf_blinds();
    BN_free(r_c);
    BN_free(r_c_inv);
    EC_GROUP_free(group); // Free the group.

}

// Helper: convert a point to 33 compressed bytes.
Element LPSIReceiver::point_to_bytes(const EC_POINT* point, BN_CTX* ctx) {
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
    Element result(len);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, result.data(), len, ctx);
    return result;
}

// Helper: convert bytes to a point.
EC_POINT* LPSIReceiver::bytes_to_point(const Element& bytes, BN_CTX* ctx) {
    EC_POINT* point = EC_POINT_new(group);
    if (!EC_POINT_oct2point(group, point, bytes.data(), bytes.size(), ctx)) {
        // Error handling.
        EC_POINT_free(point);
        return nullptr;
    }
    return point;
}

void LPSIReceiver::set_input(const ElementVector& data) {
    input_data = data;
}

Element LPSIReceiver::hash_H1(const Element& input) {
    Element result(32);
    SHA256(input.data(), input.size(), result.data());
    return result;
}

Element LPSIReceiver::hash_H2(const Element& key, const Element& data) {
    return hash_H2(key, data, 256);
}

Element LPSIReceiver::hash_H2(const Element& key, const Element& data, size_t out_len) {
    if (out_len == 0) {
        return {};
    }

    Element combined;
    combined.reserve(key.size() + data.size());
    combined.insert(combined.end(), key.begin(), key.end());
    combined.insert(combined.end(), data.begin(), data.end());
    
    Element result;
    result.reserve(out_len);
    Element current_seed = combined;
    
    while (result.size() < out_len) {
        unsigned char hash_out[32];
        SHA256(current_seed.data(), current_seed.size(), hash_out);
        size_t remaining = out_len - result.size();
        size_t take = std::min<size_t>(32, remaining);
        result.insert(result.end(), hash_out, hash_out + take);
        
        // Use the current hash output as the seed for the next round.
        current_seed.assign(hash_out, hash_out + 32);
    }
    
    return result;
}

Element LPSIReceiver::xor_elements(const Element& a, const Element& b) {
    size_t max_len = std::max(a.size(), b.size());
    Element result(max_len, 0);
    
    for (size_t i = 0; i < max_len; ++i) {
        unsigned char byte_a = (i < a.size()) ? a[i] : 0;
        unsigned char byte_b = (i < b.size()) ? b[i] : 0;
        result[i] = byte_a ^ byte_b;
    }
    
    return result;
}

void LPSIReceiver::clear_bucket_oprf_blinds() {
    for (BIGNUM* blind_inv : bucket_oprf_blind_invs) {
        if (blind_inv) {
            BN_free(blind_inv);
        }
    }
    bucket_oprf_blind_invs.clear();
}

// Phase 1: OPRF step 1, computing H(y)^r_c offline.


// Phase 1: OPRF step 3, unblinding.


ElementVector LPSIReceiver::compute_bucket_bound_oprf_step1() {
    clear_bucket_oprf_blinds();
    const size_t b=main_bucket_to_element.size();
    if(!b || element_to_main_bucket.size()!=H_y_rs.size())
        throw std::runtime_error("bucket mapping not initialized");
    std::vector<bool> occupied(b,false);
    for(size_t i=0;i<H_y_rs.size();++i){
        size_t j=element_to_main_bucket[i];
        if(j>=b || occupied[j] || main_bucket_to_element[j]!=i)
            throw std::runtime_error("invalid or duplicate local bucket assignment");
        occupied[j]=true;
    }
    bucket_oprf_blind_invs.assign(H_y_rs.size(),nullptr);
    ElementVector result(b);
    int failed=0;
    #pragma omp parallel for num_threads(get_thread_count()) reduction(|:failed)
    for(size_t j=0;j<b;++j){
        BN_CTX* ctx=BN_CTX_new();BIGNUM* order=BN_new();BIGNUM* blind=BN_new();
        EC_GROUP_get_order(group,order,ctx);
        int ok=1;do{ok=BN_priv_rand_range(blind,order);}while(ok && BN_is_zero(blind));
        EC_POINT* point=nullptr;
        if(ok && occupied[j]){
            size_t i=main_bucket_to_element[j];point=bytes_to_point(H_y_rs[i],ctx);
            bucket_oprf_blind_invs[i]=BN_mod_inverse(nullptr,blind,order,ctx);
            ok=point && bucket_oprf_blind_invs[i] && EC_POINT_mul(group,point,nullptr,point,blind,ctx)==1;
        }else if(ok){
            // Uniform nonidentity group element, indistinguishable from an occupied bucket's blind.
            point=EC_POINT_new(group);ok=point && EC_POINT_mul(group,point,blind,nullptr,nullptr,ctx)==1;
        }
        if(ok)result[j]=point_to_bytes(point,ctx);else failed=1;
        EC_POINT_free(point);BN_clear_free(blind);BN_free(order);BN_CTX_free(ctx);
    }
    if(failed){clear_bucket_oprf_blinds();throw std::runtime_error("bucket blinding failed");}
    return result;
}

void LPSIReceiver::process_bucket_bound_oprf_step3(const ElementVector& sender_output) {
    std::cout << "Receiver: processing step 3 of the second-round bucket OPRF (ECC + OpenMP)..." << std::endl;

    if(sender_output.size()!=main_bucket_to_element.size())throw std::runtime_error("bucket response length");
    bucket_bound_points.resize(H_y_rs.size());
    bucket_bound_tags.resize(H_y_rs.size());

    int failed = 0;
    #pragma omp parallel for num_threads(get_thread_count()) reduction(|:failed)
    for (size_t i = 0; i < H_y_rs.size(); ++i) {
        if (i >= bucket_oprf_blind_invs.size() || bucket_oprf_blind_invs[i] == nullptr) {
            failed = 1;
            bucket_bound_points[i].clear();
            bucket_bound_tags[i].clear();
            continue;
        }

        BN_CTX* local_ctx = BN_CTX_new();
        EC_POINT* point = bytes_to_point(sender_output[element_to_main_bucket[i]], local_ctx);
        if (!point) {
            failed = 1;
            bucket_bound_points[i].clear();
            bucket_bound_tags[i].clear();
            BN_CTX_free(local_ctx);
            continue;
        }

        if (EC_POINT_is_at_infinity(group, point) ||
            EC_POINT_mul(group, point, nullptr, point, bucket_oprf_blind_invs[i], local_ctx) != 1) {
            failed = 1;
            EC_POINT_free(point);
            BN_CTX_free(local_ctx);
            continue;
        }
        bucket_bound_points[i] = point_to_bytes(point, local_ctx);
        bucket_bound_tags[i] = hash_H1(bucket_bound_points[i]);

        EC_POINT_free(point);
        BN_CTX_free(local_ctx);
    }

    clear_bucket_oprf_blinds();
    if (failed) {
        bucket_bound_points.clear();
        bucket_bound_tags.clear();
        throw std::runtime_error("invalid bucket response or missing request state");
    }
}

// Save data to a file in hexadecimal format.


// Phase 2: Build main buckets using cuckoo hashing to assign each receiver element to one unique bucket.
void LPSIReceiver::build_hash_buckets(size_t bucket_count, int num_hash_funcs)
{
    std::cout << "Receiver: building main buckets with cuckoo hashing..." << std::endl;
    double total_start = omp_get_wtime();

    // Prepare output structures.
    Y_star.clear();
    Y_star.resize(bucket_count);
    // Use bucket_count as the invalid index; valid indices range from 0 to bucket_count-1.
    size_t INVALID_BUCKET = bucket_count;
    element_to_main_bucket.assign(Y_prime.size(), INVALID_BUCKET);
    main_bucket_to_element.assign(bucket_count, Y_prime.size());
    
    // Record the element index in each bucket; INVALID_BUCKET denotes an empty bucket.
    std::vector<size_t> bucket_to_element(bucket_count, INVALID_BUCKET);
    std::vector<size_t> candidate_cache(Y_prime.size() * static_cast<size_t>(num_hash_funcs));

    double prehash_start = omp_get_wtime();
    #pragma omp parallel for num_threads(get_thread_count()) schedule(static)
    for (size_t y_idx = 0; y_idx < Y_prime.size(); ++y_idx) {
        size_t base = y_idx * static_cast<size_t>(num_hash_funcs);
        for (int h = 0; h < num_hash_funcs; ++h) {
            candidate_cache[base + static_cast<size_t>(h)] =
                instance_hash(Y_prime[y_idx], h, bucket_count);
        }
    }
    double prehash_time_ms = (omp_get_wtime() - prehash_start) * 1000.0;

    size_t cur_MAX_RETRY = LPSIConfig::MAX_RETRY;
    std::mt19937 rng(0xDEADBEEFU);
    std::uniform_int_distribution<int> victim_dist(0, num_hash_funcs - 1);

    // // Save the main cuckoo hash input to a file.
    
    // Iterate over all receiver elements.
    double cuckoo_start = omp_get_wtime();
    for (size_t y_idx = 0; y_idx < Y_prime.size(); ++y_idx)
    {
        // Try to insert the current element.
        size_t current_idx = y_idx;
        const size_t* current_candidates =
            candidate_cache.data() + current_idx * static_cast<size_t>(num_hash_funcs);
        
        bool inserted = false;
        for (size_t retry = 0; retry < cur_MAX_RETRY && !inserted; ++retry)
        {
            // Try all candidate buckets.
            for (int k = 0; k < num_hash_funcs; ++k)
            {
                size_t b = current_candidates[k];
                
                // Insert directly if the bucket is empty.
                if (bucket_to_element[b] == INVALID_BUCKET)
                {
                    bucket_to_element[b] = current_idx;
                    element_to_main_bucket[current_idx] = b;
                    inserted = true;
                    break;
                }
            }
            
            if (!inserted)
            {
                // All candidate buckets are occupied; evict an element at random.
                size_t victim_bucket = current_candidates[victim_dist(rng)];
                size_t victim_idx = bucket_to_element[victim_bucket];

                // Place the current element in the bucket.
                bucket_to_element[victim_bucket] = current_idx;
                element_to_main_bucket[current_idx] = victim_bucket;
                
                // Prepare to reinsert the evicted element.
                current_idx = victim_idx;
                current_candidates =
                    candidate_cache.data() + current_idx * static_cast<size_t>(num_hash_funcs);
            }
        }
        
        if (!inserted)
        {
            // Do not fall back silently: this would leave element_to_main_bucket pointing to an incorrect bucket and silently corrupt data.
            // Throw an exception so the caller can retry with a larger B.
            throw std::runtime_error(
                "Outer cuckoo hashing failed: B=" + std::to_string(bucket_count) +
                " for R=" + std::to_string(Y_prime.size()) + " elements; increase B and retry.");
        }
    }
    double cuckoo_time_ms = (omp_get_wtime() - cuckoo_start) * 1000.0;
    
    // Verify that every element has a unique assignment and both mapping tables agree.
    double verify_start = omp_get_wtime();
    bool unique_mapping = true;
    size_t inconsistent_count = 0;
    std::vector<uint8_t> used_buckets(bucket_count, 0);
    for (size_t y_idx = 0; y_idx < Y_prime.size(); ++y_idx)
    {
        size_t bucket = element_to_main_bucket[y_idx];
        if (bucket == INVALID_BUCKET)
        {
            std::cerr << "Error: element " << y_idx << " is not assigned to any main bucket." << std::endl;
            unique_mapping = false;
            continue;
        }
        // Validate that bucket_to_element and element_to_main_bucket are inverse mappings.
        if (bucket_to_element[bucket] != y_idx) {
            inconsistent_count++;
            if (inconsistent_count <= 5) {
                std::cerr << "[Inconsistent cuckoo mapping] Element[" << y_idx << "] claims bucket[" << bucket
                          << "], but that bucket records element[" << bucket_to_element[bucket] << "]" << std::endl;
            }
            unique_mapping = false;
        }
        if (used_buckets[bucket] != 0)
        {
            std::cerr << "Error: main bucket " << bucket << " is assigned to multiple elements." << std::endl;
            unique_mapping = false;
        }
        used_buckets[bucket] = 1;
    }

    for (size_t bucket = 0; bucket < bucket_to_element.size(); ++bucket) {
        size_t elem_idx = bucket_to_element[bucket];
        if (elem_idx != INVALID_BUCKET) {
            main_bucket_to_element[bucket] = elem_idx;
        }
    }
    double verify_time_ms = (omp_get_wtime() - verify_start) * 1000.0;
    
    // Print mapping information for debugging.
    
    if (unique_mapping)
    {
        std::cout << "[OK] All elements are assigned to unique main buckets." << std::endl;
        std::cout << "Receiver: main-bucket timing breakdown"
                  << " [prehash " << std::fixed << std::setprecision(1) << prehash_time_ms
                  << " ms, cuckoo insertion " << cuckoo_time_ms
                  << " ms, validation " << verify_time_ms
                  << " ms, total " << ((omp_get_wtime() - total_start) * 1000.0)
                  << " ms]" << std::endl;
    }
    else
    {
        std::cerr << "[FAIL] Main-bucket mapping has collisions or unassigned elements." << std::endl;
        throw std::runtime_error("Main-bucket mapping failed: collisions or unassigned elements.");
    }
    
}

// Phase 2: Sub-bucket hashing uses multiple simple hash functions to produce nh candidate positions.
void LPSIReceiver::build_sub_buckets(size_t sender_data_size, size_t num_main_buckets, int nh) {
    
    // The receiver need not build sub-buckets; phase 3 computes hashes using the sender's capacity parameters.
    // Reserve the structure here for validation.
    Y_sub_star.resize(Y_star.size());
    for (size_t main_idx = 0; main_idx < Y_star.size(); ++main_idx) {
        Y_sub_star[main_idx].resize(nh);
    }
    for (size_t y_idx = 0; y_idx < Y_prime.size(); ++y_idx) {
        
    }
    
}

// Phase 3: Generate PIR query indices corresponding to the sender's Kuku cuckoo hash positions.
void LPSIReceiver::generate_pir_query_indices(size_t sender_num_main_buckets,
                                                size_t sender_nh,
                                                size_t sender_sub_capacity) {
    double total_start = omp_get_wtime();
    // Store the sender's bucket structure.
    this->sender_num_main_buckets = sender_num_main_buckets;
    this->sender_nh = sender_nh;
    this->sender_sub_capacity = sender_sub_capacity;
    
    std::cout << "Sender bucket structure: " << sender_num_main_buckets << " main buckets, "
              << sender_nh << " sub-buckets, each with capacity " << sender_sub_capacity << std::endl;
    
    query_indices.assign(sender_num_main_buckets, std::vector<size_t>(sender_nh, 0));
    valid_bucket_indices.resize(sender_num_main_buckets);
    std::iota(valid_bucket_indices.begin(), valid_bucket_indices.end(), 0);
    
    // Use the same instance_hash function as the sender and the validation phase.
    
    // Generate queries for each main bucket.
    double fill_start = omp_get_wtime();
    #pragma omp parallel for num_threads(get_thread_count()) schedule(static)
    for (size_t main_idx = 0; main_idx < sender_num_main_buckets; ++main_idx) {
        auto& local_query_indices = query_indices[main_idx];
        size_t mapped_y_idx = main_idx < main_bucket_to_element.size()
            ? main_bucket_to_element[main_idx]
            : element_to_main_bucket.size();

        if (mapped_y_idx < bucket_bound_tags.size() &&
            !bucket_bound_tags[mapped_y_idx].empty()) {
            const Element& y_bucket_tag = bucket_bound_tags[mapped_y_idx];
            for (size_t h = 0; h < sender_nh; ++h) {
                local_query_indices[h] = instance_hash(y_bucket_tag, 10 + h, sender_sub_capacity);
            }
        } else {
            std::mt19937 gen(0xBADC0DEu ^ static_cast<uint32_t>(main_idx));
            std::uniform_int_distribution<size_t> dis(0, sender_sub_capacity - 1);
            for (size_t h = 0; h < sender_nh; ++h) {
                local_query_indices[h] = dis(gen);
            }
        }
    }
    double fill_time_ms = (omp_get_wtime() - fill_start) * 1000.0;
    
    std::cout << "Receiver: PIR query indices generated; main buckets = " << query_indices.size() 
              << ", total queries = " << (query_indices.size() * sender_nh) << std::endl;
    double y_inflation = static_cast<double>(query_indices.size() * sender_nh) / static_cast<double>(input_data.size());
    std::cout << "  PIR query expansion relative to the original query set Y: x" << y_inflation << std::endl;
    std::cout << "Receiver: PIR query-index timing breakdown"
              << " [fill " << std::fixed << std::setprecision(1) << fill_time_ms
              << " ms, total " << ((omp_get_wtime() - total_start) * 1000.0)
              << " ms]" << std::endl;
}

std::vector<uint32_t> LPSIReceiver::get_query_indices_flat() const {
    double flatten_start = omp_get_wtime();
    std::vector<uint32_t> flat;
    flat.reserve(query_indices.size() * sender_nh);

    for (size_t main_idx = 0; main_idx < query_indices.size(); ++main_idx) {
        const auto& local_indices = query_indices[main_idx];

        for (size_t h = 0; h < sender_nh; ++h) {
            size_t virtual_row = main_idx * sender_nh + h;
            size_t slot = local_indices[h];

            if (slot >= sender_sub_capacity) {
                slot = sender_sub_capacity - 1;
            }

            size_t global_idx = virtual_row * sender_sub_capacity + slot;
            flat.push_back(static_cast<uint32_t>(global_idx));
        }
    }

    std::cout << "Receiver: PIR query expansion complete"
              << " [total " << std::fixed << std::setprecision(1)
              << ((omp_get_wtime() - flatten_start) * 1000.0) << " ms]" << std::endl;
    return flat;
}

void LPSIReceiver::process_pir_results(const std::vector<Element>& results) {
    double process_start = omp_get_wtime();
    pir_results = results;
    
    hit_element_indices.clear();
    hit_sub_bucket_indices.clear();

    std::vector<size_t> matched_sub_bucket(query_indices.size(), sender_nh);

    #pragma omp parallel for num_threads(get_thread_count()) schedule(static)
    for (size_t main_idx = 0; main_idx < query_indices.size(); ++main_idx) {
        size_t elem_idx = main_idx < main_bucket_to_element.size()
            ? main_bucket_to_element[main_idx]
            : Y_prime.size();
        if (elem_idx >= Y_prime.size()) {
            continue;
        }

        size_t base_idx = main_idx * sender_nh;
        for (size_t h = 0; h < sender_nh; ++h) {
            size_t result_idx = base_idx + h;
            if (result_idx >= pir_results.size()) {
                break;
            }

            const Element& pir_result = pir_results[result_idx];
            if (pir_result.size() < 32) {
                continue;
            }

            if (elem_idx < bucket_bound_tags.size() &&
                !bucket_bound_tags[elem_idx].empty() &&
                std::equal(pir_result.begin(), pir_result.begin() + 32,
                           bucket_bound_tags[elem_idx].begin())) {
                matched_sub_bucket[main_idx] = h;
                break;
            }
        }
    }

    hit_element_indices.reserve(Y_prime.size());
    hit_sub_bucket_indices.reserve(Y_prime.size());
    for (size_t main_idx = 0; main_idx < matched_sub_bucket.size(); ++main_idx) {
        size_t matched_h = matched_sub_bucket[main_idx];
        if (matched_h >= sender_nh) {
            continue;
        }
        size_t elem_idx = main_bucket_to_element[main_idx];
        if (elem_idx < Y_prime.size()) {
            hit_element_indices.push_back(elem_idx);
            hit_sub_bucket_indices.push_back(matched_h);
        }
    }

    std::cout << "Receiver: PIR hit filtering complete"
              << " [hits " << hit_element_indices.size() << "/" << Y_prime.size()
              << ", total " << std::fixed << std::setprecision(1)
              << ((omp_get_wtime() - process_start) * 1000.0) << " ms]" << std::endl;
}

std::vector<size_t> LPSIReceiver::get_delivery_choices() const {
    std::vector<size_t> choices;
    
    // Return the main bucket index for each matching element.
    for (size_t elem_idx : hit_element_indices) {
        if (elem_idx < element_to_main_bucket.size()) {
            choices.push_back(element_to_main_bucket[elem_idx]);
        }
    }
    
    std::cout << "Receiver: gen " << choices.size() << " choice idxs" << std::endl;
    return choices;
}

// Phase 6: Decrypt the intersection, processing matching elements only.
// masked_value has no header: encrypted(x||v).
// x_len = item_byte_ and v_len = label_byte_, as specified by the protocol parameters.
void LPSIReceiver::decrypt_intersection(const std::vector<Element>& bucket_keys) {
    std::cout << "\n========== Decrypting the intersection ==========" << std::endl;
    std::cout << "Processing " << hit_element_indices.size() << " matching elements "
              << "(item_byte=" << item_byte_ << ", label_byte=" << label_byte_ << ")..." << std::endl;

    if (bucket_keys.size() != hit_element_indices.size()) {
        std::cout << "Warning: bucket_keys count (" << bucket_keys.size()
                  << ") does not match the hit count (" << hit_element_indices.size() << ")." << std::endl;
    }

    if (hit_element_indices.size() != hit_sub_bucket_indices.size()) {
        std::cout << "Error: hit_element_indices and hit_sub_bucket_indices have different sizes." << std::endl;
        return;
    }

    size_t n = hit_element_indices.size();
    // Preallocate result slots and write to distinct slots in parallel.
    std::vector<std::pair<Element, Element>> tmp_intersection(n);
    std::vector<int> valid(n, 0);  // int, not bool: vector<bool> packs bits → data race

    size_t data_len = item_byte_ + label_byte_;  // Without a header, the data length is simply the length of x||v.

    #pragma omp parallel for num_threads(g_thread_count) schedule(dynamic)
    for (size_t key_idx = 0; key_idx < n; ++key_idx) {
        size_t elem_idx       = hit_element_indices[key_idx];
        size_t sub_bucket_idx = hit_sub_bucket_indices[key_idx];

        if (elem_idx >= element_to_main_bucket.size()) continue;

        size_t main_bucket_idx = element_to_main_bucket[elem_idx];
        if (main_bucket_idx >= query_indices.size()) continue;

        const auto& indices = query_indices[main_bucket_idx];
        if (key_idx >= bucket_keys.size()) continue;
        if (sub_bucket_idx >= indices.size()) continue;

        const Element& s_j = bucket_keys[key_idx];

        size_t result_idx = main_bucket_idx * sender_nh + sub_bucket_idx;
        if (result_idx >= pir_results.size()) continue;

        const Element& pir_result = pir_results[result_idx];
        if (pir_result.size() < 32) continue;

        // Verify the bucket-bound key again; process_pir_results has already confirmed the hit marker.
        Element pir_key(pir_result.begin(), pir_result.begin() + 32);
        if (elem_idx >= bucket_bound_tags.size() || pir_key != bucket_bound_tags[elem_idx]) continue;

        // Extract data_len bytes of encrypted(x||v) starting at byte offset 32.
        if (pir_result.size() < 32 + data_len) continue;
        Element encrypted_data(pir_result.begin() + 32, pir_result.begin() + 32 + data_len);

        if (elem_idx >= bucket_bound_points.size() || bucket_bound_points[elem_idx].empty()) continue;

        // Decrypt: x||v = encrypted_data XOR H_2(s_j, (H(y)^r_s)^{l_j}).
        Element h2_result = hash_H2(s_j, bucket_bound_points[elem_idx], data_len);

        Element decrypted = xor_elements(encrypted_data, h2_result);

        Element x(decrypted.begin(), decrypted.begin() + item_byte_);
        Element v(decrypted.begin() + item_byte_, decrypted.end());

        tmp_intersection[key_idx] = {x, v};
        valid[key_idx] = 1;
    }

    // Collect valid results in order.
    intersection.clear();
    for (size_t i = 0; i < n; ++i) {
        if (valid[i] != 0) intersection.push_back(std::move(tmp_intersection[i]));
    }

    std::cout << "\n========== Decryption complete ==========" << std::endl;
    std::cout << "Receiver: decrypted intersection size = " << intersection.size() << std::endl;
}

void LPSIReceiver::cx_set_encodings(const ElementVector& points) {
    if (points.size() != input_data.size()) throw std::runtime_error("CX receiver size mismatch");
    H_y_rs=points;Y_prime.resize(points.size());
    for (size_t i=0;i<points.size();++i) Y_prime[i]=hash_H1(points[i]);
}

// Select paired hit/sub-bucket entries together. No unselected key is released.
void LPSIReceiver::cx_select_purchases(size_t tau) {
    if(tau>hit_element_indices.size()||hit_element_indices.size()!=hit_sub_bucket_indices.size())
        throw std::runtime_error("invalid purchase count or hit mapping");
    // Fisher-Yates with rejection sampling, using fresh OS randomness.
    auto n=hit_element_indices.size();
    for(size_t i=0;i<tau;++i){
        uint64_t r,range=n-i,limit=UINT64_MAX-(UINT64_MAX%range);
        do {if(RAND_bytes(reinterpret_cast<unsigned char*>(&r),sizeof(r))!=1)throw std::runtime_error("purchase RNG");}while(r>=limit);
        size_t j=i+r%range;
        std::swap(hit_element_indices[i],hit_element_indices[j]);
        std::swap(hit_sub_bucket_indices[i],hit_sub_bucket_indices[j]);
    }
    hit_element_indices.resize(tau);hit_sub_bucket_indices.resize(tau);
}
