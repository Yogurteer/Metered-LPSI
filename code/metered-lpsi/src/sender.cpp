#include "sender.h"
#include "config.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <cstring>
#include <cmath>
#include <algorithm>
#include <iostream>
#include <iomanip>
#include <random>
#include <set>
#include <unordered_set>
#include <atomic>
#include <stdexcept>
#include <omp.h>

namespace {

BIGNUM* sample_nonzero_scalar(const EC_GROUP* group) {
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);

    BIGNUM* scalar = BN_new();
    do {
        BN_rand_range(scalar, order);
    } while (BN_is_zero(scalar));

    BN_free(order);
    BN_CTX_free(ctx);
    return scalar;
}

}  // namespace

LPSISender::LPSISender(size_t item_byte, size_t label_byte)
    : item_byte_(item_byte), label_byte_(label_byte) {
    // Initialize the P-256 curve.
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);

    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx);
    r_s = BN_new();
    BN_rand_range(r_s, order);
    BN_free(order);
    BN_CTX_free(ctx);

}

LPSISender::LPSISender(){
    // Initialize the P-256 curve.
    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    
    // Generate the random scalar r_s in [1, order-1].
    BN_CTX* ctx = BN_CTX_new();
    BIGNUM* order = BN_new();
    EC_GROUP_get_order(group, order, ctx); // Obtain the group order.
    
    r_s = BN_new();
    BN_rand_range(r_s, order); // Generate a random value.
    
    BN_free(order);
    BN_CTX_free(ctx);
    
}

LPSISender::~LPSISender() {
    for(auto& scalar:private_encoding_scalars)OPENSSL_cleanse(scalar.data(),scalar.size());
    clear_bucket_oprf_exponents();
    BN_free(r_s);
    EC_GROUP_free(group); // Free the group.
}

// Helper: convert a point to 33 compressed bytes.
Element LPSISender::point_to_bytes(const EC_POINT* point, BN_CTX* ctx) {
    size_t len = EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, nullptr, 0, ctx);
    Element result(len);
    EC_POINT_point2oct(group, point, POINT_CONVERSION_COMPRESSED, result.data(), len, ctx);
    return result;
}

// Helper: convert bytes to a point.
EC_POINT* LPSISender::bytes_to_point(const Element& bytes, BN_CTX* ctx) {
    EC_POINT* point = EC_POINT_new(group);
    if (!EC_POINT_oct2point(group, point, bytes.data(), bytes.size(), ctx)) {
        // Error handling.
        EC_POINT_free(point);
        return nullptr;
    }
    return point;
}

void LPSISender::set_input(const std::vector<std::pair<Element, Element>>& data) {
    input_data = data;
}

// Hash function H1: G -> {0,1}^lambda.
Element LPSISender::hash_H1(const Element& input) {
    Element result(32);
    SHA256(input.data(), input.size(), result.data());
    return result;
}

// Hash function H2: {0,1}^lambda x G -> {0,1}^L.
Element LPSISender::hash_H2(const Element& key, const Element& data) {
    return hash_H2(key, data, 256);
}

Element LPSISender::hash_H2(const Element& key, const Element& data, size_t out_len) {
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

void LPSISender::xor_with_hash_H2(
    const Element& key,
    const Element& data,
    const Element& input,
    Element& output) {
    output.resize(input.size());
    if (input.empty()) {
        return;
    }

    std::array<unsigned char, 96> initial_input{};
    size_t initial_len = key.size() + data.size();
    if (initial_len > initial_input.size()) {
        Element h2_result = hash_H2(key, data, input.size());
        for (size_t i = 0; i < input.size(); ++i) {
            output[i] = input[i] ^ h2_result[i];
        }
        return;
    }

    std::memcpy(initial_input.data(), key.data(), key.size());
    std::memcpy(initial_input.data() + key.size(), data.data(), data.size());

    unsigned char block[32];
    SHA256(initial_input.data(), initial_len, block);

    size_t produced = 0;
    while (produced < input.size()) {
        size_t take = std::min<size_t>(32, input.size() - produced);
        for (size_t j = 0; j < take; ++j) {
            output[produced + j] = input[produced + j] ^ block[j];
        }
        produced += take;
        if (produced < input.size()) {
            SHA256(block, sizeof(block), block);
        }
    }
}

Element LPSISender::xor_elements(const Element& a, const Element& b) {
    size_t max_len = std::max(a.size(), b.size());
    Element result(max_len, 0);
    
    for (size_t i = 0; i < max_len; ++i) {
        unsigned char byte_a = (i < a.size()) ? a[i] : 0;
        unsigned char byte_b = (i < b.size()) ? b[i] : 0;
        result[i] = byte_a ^ byte_b;
    }
    
    return result;
}

void LPSISender::clear_bucket_oprf_exponents() {
    for (BIGNUM* exponent : bucket_oprf_exponents) {
        if (exponent) {
            BN_free(exponent);
        }
    }
    bucket_oprf_exponents.clear();
}

// Compute X' = H_1(H(x)^r_s).

// Phase 2: Build main buckets using three-way simple hashing, creating sender-side copies.
void LPSISender::build_hash_buckets(size_t num_main_buckets, int num_hash_funcs) {
    double total_start = omp_get_wtime();

    // Use the configured multiplier consistently with the receiver.

    num_main_b = num_main_buckets;
    size_t bucket_count = num_main_buckets;
    X_star.clear();
    X_star.resize(num_main_b);
    clear_bucket_oprf_exponents();
    bucket_keys.clear();
    
    double keygen_time_ms = 0.0;

    size_t num_items = X_prime.size();
    int worker_threads = std::max(1, std::min<int>(get_thread_count(), static_cast<int>(std::max<size_t>(1, num_items))));
    std::vector<uint32_t> bucket_indices(num_items * static_cast<size_t>(num_hash_funcs));
    std::vector<std::vector<uint32_t>> local_counts(worker_threads, std::vector<uint32_t>(bucket_count, 0));
    std::vector<kuku::LocFunc> outer_loc_funcs;
    outer_loc_funcs.reserve(num_hash_funcs);
    for (int h = 0; h < num_hash_funcs; ++h) {
        uint64_t seed_low = 0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(h + 1);
        uint64_t seed_high = seed_low ^ 0xD1B54A32D192ED03ULL;
        kuku::item_type seed_item = kuku::make_item(seed_low, seed_high);
        outer_loc_funcs.emplace_back(static_cast<kuku::table_size_type>(bucket_count), seed_item);
    }

    double assign_start = omp_get_wtime();
    #pragma omp parallel num_threads(worker_threads)
    {
        int tid = omp_get_thread_num();
        size_t start = num_items * static_cast<size_t>(tid) / static_cast<size_t>(worker_threads);
        size_t end = num_items * static_cast<size_t>(tid + 1) / static_cast<size_t>(worker_threads);
        auto& counts = local_counts[tid];

        for (size_t i = start; i < end; ++i) {
            size_t base = i * static_cast<size_t>(num_hash_funcs);
            kuku::item_type item = make_item_from_bytes(X_prime[i]);
            for (int h = 0; h < num_hash_funcs; ++h) {
                uint32_t bucket_idx = static_cast<uint32_t>(
                    outer_loc_funcs[h](item) % static_cast<kuku::table_size_type>(bucket_count));
                bucket_indices[base + static_cast<size_t>(h)] = bucket_idx;
                counts[bucket_idx] += 1;
            }
        }
    }
    double assign_time_ms = (omp_get_wtime() - assign_start) * 1000.0;

    double alloc_start = omp_get_wtime();
    for (size_t bucket_idx = 0; bucket_idx < bucket_count; ++bucket_idx) {
        size_t total = 0;
        for (int tid = 0; tid < worker_threads; ++tid) {
            total += local_counts[tid][bucket_idx];
        }
        X_star[bucket_idx].resize(total);
    }

    std::vector<std::vector<size_t>> thread_offsets(worker_threads, std::vector<size_t>(bucket_count, 0));
    for (size_t bucket_idx = 0; bucket_idx < bucket_count; ++bucket_idx) {
        size_t offset = 0;
        for (int tid = 0; tid < worker_threads; ++tid) {
            thread_offsets[tid][bucket_idx] = offset;
            offset += local_counts[tid][bucket_idx];
        }
    }
    double alloc_time_ms = (omp_get_wtime() - alloc_start) * 1000.0;

    double fill_start = omp_get_wtime();
    #pragma omp parallel num_threads(worker_threads)
    {
        int tid = omp_get_thread_num();
        size_t start = num_items * static_cast<size_t>(tid) / static_cast<size_t>(worker_threads);
        size_t end = num_items * static_cast<size_t>(tid + 1) / static_cast<size_t>(worker_threads);
        auto& offsets = thread_offsets[tid];

        for (size_t i = start; i < end; ++i) {
            size_t base = i * static_cast<size_t>(num_hash_funcs);
            for (int h = 0; h < num_hash_funcs; ++h) {
                size_t bucket_idx = bucket_indices[base + static_cast<size_t>(h)];
                size_t pos = offsets[bucket_idx]++;
                SenderBucketData data;
                data.source_index = i;
                X_star[bucket_idx][pos] = std::move(data);
            }
        }
    }
    double fill_time_ms = (omp_get_wtime() - fill_start) * 1000.0;

    std::cout << "Sender: main-bucket timing breakdown"
              << " [keygen " << std::fixed << std::setprecision(1)
              << keygen_time_ms
              << " ms, pre-bucketing " << assign_time_ms
              << " ms, allocation " << alloc_time_ms
              << " ms, fill " << fill_time_ms
              << " ms, total " << ((omp_get_wtime() - total_start) * 1000.0)
              << " ms]" << std::endl;
}

void LPSISender::prepare_bucket_bound_entries() {
    bucket_oprf_consumed=false;
    if (X_star.empty()) {
        clear_bucket_oprf_exponents();
        bucket_keys.clear();
        return;
    }

    clear_bucket_oprf_exponents();
    bucket_oprf_exponents.resize(num_main_b, nullptr);
    bucket_keys.assign(num_main_b, Element(LPSIConfig::BUCKET_KEY_SIZE_BYTES, 0));

    bucket_keys = cx_delivery.prepare(num_main_b, g_thread_count);
    for (size_t bucket_idx=0;bucket_idx<num_main_b;++bucket_idx) {
        bucket_oprf_exponents[bucket_idx]=sample_nonzero_scalar(group);
    }

    #pragma omp parallel for num_threads(get_thread_count()) schedule(dynamic)
    for (size_t main_idx = 0; main_idx < X_star.size(); ++main_idx) {
        BN_CTX* local_ctx = BN_CTX_new();
        const BIGNUM* l_j = bucket_oprf_exponents[main_idx];
        const Element& s_j = bucket_keys[main_idx];

        for (auto& bucket_item : X_star[main_idx]) {
            if (bucket_item.source_index >= input_data.size() ||
                bucket_item.source_index >= H_x_rs_bytes.size()) {
                bucket_item.pir_key.clear();
                bucket_item.masked_value.clear();
                continue;
            }

            const size_t source_index = bucket_item.source_index;
            const Element& scalar = private_encoding_scalars[source_index];
            BN_CTX_start(local_ctx);
            BIGNUM* e=BN_CTX_get(local_ctx);BIGNUM* q=BN_CTX_get(local_ctx);
            BN_bin2bn(scalar.data(),scalar.size(),e);EC_GROUP_get_order(group,q,local_ctx);
            BN_mod_mul(e,e,l_j,q,local_ctx);
            EC_POINT* point=EC_POINT_new(group);
            EC_POINT_mul(group,point,e,nullptr,nullptr,local_ctx);
            Element q_ij=point_to_bytes(point,local_ctx);
            EC_POINT_free(point);BN_CTX_end(local_ctx);

            bucket_item.pir_key = hash_H1(q_ij);

            const Element& x = input_data[source_index].first;
            const Element& v = input_data[source_index].second;
            Element x_concat_v;
            x_concat_v.reserve(x.size() + v.size());
            x_concat_v.insert(x_concat_v.end(), x.begin(), x.end());
            x_concat_v.insert(x_concat_v.end(), v.begin(), v.end());
            xor_with_hash_H2(s_j, q_ij, x_concat_v, bucket_item.masked_value);
        }

        BN_CTX_free(local_ctx);
    }
}

ElementVector LPSISender::process_bucket_oprf_step2(const ElementVector& receiver_masked) {
    if(bucket_oprf_consumed)throw std::runtime_error("bucket evaluation already consumed");
    bucket_oprf_consumed=true; // Failed requests consume this instance too.
    const size_t b=bucket_oprf_exponents.size();
    if(!b || receiver_masked.size()!=b)throw std::runtime_error("expected exactly b bucket queries");
    // Validate the entire request before releasing any result. No bucket identifiers on the wire.
    BN_CTX* ctx=BN_CTX_new();
    bool valid=true;
    for(const auto& bytes:receiver_masked){
        EC_POINT* p=bytes.size()==33?bytes_to_point(bytes,ctx):nullptr;
        if(!p || EC_POINT_is_at_infinity(group,p) || EC_POINT_is_on_curve(group,p,ctx)!=1 || point_to_bytes(p,ctx)!=bytes)valid=false;
        EC_POINT_free(p);
    }
    BN_CTX_free(ctx);
    if(!valid)throw std::runtime_error("invalid bucket query point");
    ElementVector result(b);int failed=0;
    #pragma omp parallel for num_threads(get_thread_count()) reduction(|:failed)
    for(size_t j=0;j<b;++j){
        BN_CTX* local=BN_CTX_new();EC_POINT* point=bytes_to_point(receiver_masked[j],local);
        if(!point || EC_POINT_mul(group,point,nullptr,point,bucket_oprf_exponents[j],local)!=1)failed=1;
        else result[j]=point_to_bytes(point,local);
        EC_POINT_free(point);BN_CTX_free(local);
    }
    if(failed)throw std::runtime_error("bucket evaluation failed");
    return result;
}

// Phase 2: Build sub-buckets using Kuku cuckoo hashing on the sender.
void LPSISender::build_sub_buckets(size_t sender_data_size, size_t num_main_buckets, int nh) {
    double total_start = omp_get_wtime();

    if (X_star.empty()) {
        X_sub_star.clear();
        return;
    }
    if (bucket_keys.size() != num_main_b || bucket_oprf_exponents.size() != num_main_b) {
        throw std::runtime_error("Sender bucket-binding material is not ready; cannot build sub-buckets.");
    }

    // Compute sub-bucket capacity dynamically.
    size_t max_main_bucket_size = 0;
    size_t non_empty_buckets = 0;
    for (const auto& bucket : X_star) {
        if (!bucket.empty()) {
            non_empty_buckets++;
            max_main_bucket_size = std::max(max_main_bucket_size, bucket.size());
        }
    }
    
    // Choose sub-bucket capacity so nh-way cuckoo insertion converges at the current load.
    // SUB_BUCKET_FACTOR=0.6 gives about 55% load for nh=3, below the approximately 91% three-way cuckoo load threshold.
    size_t sub_bucket_capacity = static_cast<size_t>(
        std::ceil(max_main_bucket_size * LPSIConfig::SUB_BUCKET_FACTOR));

    std::cout << "[Sub-bucket capacity] nh=" << nh
              << ", max_bucket=" << max_main_bucket_size
              << " -> capacity per sub-bucket=" << sub_bucket_capacity
              << ", total capacity=" << (sub_bucket_capacity * nh)
              << ", actual load=" << std::fixed << std::setprecision(1)
              << (static_cast<double>(max_main_bucket_size) / (sub_bucket_capacity * nh) * 100) << "%" << std::endl;
    

    // Clear old data to prevent stale entries on retries.
    X_sub_star.clear();
    X_sub_star.resize(X_star.size());

    // OpenMP-safe error flag: exit(1) inside parallel region is unreliable
    std::atomic<bool> any_inner_failure(false);
    std::atomic<size_t> failed_main_idx(SIZE_MAX);
    std::vector<kuku::LocFunc> inner_loc_funcs;
    inner_loc_funcs.reserve(nh);
    for (int h = 0; h < nh; ++h) {
        int hash_idx = 10 + h;
        uint64_t seed_low = 0x9E3779B97F4A7C15ULL * static_cast<uint64_t>(hash_idx + 1);
        uint64_t seed_high = seed_low ^ 0xD1B54A32D192ED03ULL;
        kuku::item_type seed_item = kuku::make_item(seed_low, seed_high);
        inner_loc_funcs.emplace_back(static_cast<kuku::table_size_type>(sub_bucket_capacity), seed_item);
    }

    // Build an independent inner Kuku hash table for each main bucket; these can be processed in parallel.
    #pragma omp parallel for num_threads(get_thread_count()) schedule(dynamic)
    for (size_t main_idx = 0; main_idx < X_star.size(); ++main_idx) {
        if (any_inner_failure.load(std::memory_order_relaxed)) continue;
        // Use a per-thread RNG with a fixed seed plus main_idx for deterministic behavior; this code is re-entered on retry.
        std::mt19937 rng(0xCAFEBABEu ^ (uint32_t)main_idx);
        // Initialize the sub-bucket structure.
        X_sub_star[main_idx].resize(nh);
        for (int sub_idx = 0; sub_idx < nh; ++sub_idx) {
            X_sub_star[main_idx][sub_idx].resize(sub_bucket_capacity);
        }
        
        const auto& main_bucket = X_star[main_idx];
        if (main_bucket.empty()) continue;
        
        // Deduplicate entries: outer simple-hash collisions in a main bucket can otherwise create duplicates that disrupt inner cuckoo hashing.
        std::vector<SenderBucketData> unique_elements;
        unique_elements.reserve(main_bucket.size());
        std::unordered_set<std::string> seen_x_primes;
        seen_x_primes.reserve(main_bucket.size() * 2);
        
        for (const auto& data : main_bucket) {
            if (data.pir_key.empty()) {
                continue;
            }
            std::string key(
                reinterpret_cast<const char*>(data.pir_key.data()),
                data.pir_key.size());
            if (seen_x_primes.insert(std::move(key)).second) {
                unique_elements.push_back(data);
            }
        }
        
        // Use cuckoo hashing with eviction to assign a position to each unique element.
        bool bucket_success = true;
        
        for (const auto& initial_elem : unique_elements) {
            SenderBucketData current_item = initial_elem;
            bool placed = false;
            std::vector<size_t> current_slots(nh, 0);
            auto refresh_slots = [&](const Element& pir_key) {
                kuku::item_type item = make_item_from_bytes(pir_key);
                for (int h = 0; h < nh; ++h) {
                    current_slots[h] = inner_loc_funcs[h](item) %
                        static_cast<kuku::table_size_type>(sub_bucket_capacity);
                }
            };
            refresh_slots(current_item.pir_key);
            
            // Attempt insertion with eviction.
            // Use the configured maximum retry count.
            int max_retries = LPSIConfig::MAX_RETRY; 
            if (max_retries <= 0) max_retries = 500; // Guard the default value.
            
            for (int retry = 0; retry < max_retries; ++retry) {
                // 1. Look for an empty slot among the nh candidates.
                int empty_h = -1;
                size_t empty_slot = 0;
                
                for (int h = 0; h < nh; ++h) {
                    size_t slot = current_slots[h];
                    if (X_sub_star[main_idx][h][slot].pir_key.empty()) {
                        empty_h = h;
                        empty_slot = slot;
                        break;
                    }
                }
                
                // 2. If a slot is available, insert the element and finish processing it.
                if (empty_h != -1) {
                    X_sub_star[main_idx][empty_h][empty_slot] = current_item;
                    placed = true;
                    break;
                }
                
                // 3. Otherwise, evict a randomly chosen element.
                // Select a sub-bucket at random.
                std::uniform_int_distribution<int> dist(0, nh - 1);
                int victim_h = dist(rng);
                size_t victim_slot = current_slots[victim_h];
                
                // Swap: insert the new element and make the evicted element current_item for the next insertion attempt.
                SenderBucketData victim_item = X_sub_star[main_idx][victim_h][victim_slot];
                X_sub_star[main_idx][victim_h][victim_slot] = current_item;
                current_item = victim_item;
                refresh_slots(current_item.pir_key);
                
                // Continue the loop to reinsert victim_item.
            }
            
            if (!placed) {
                std::cerr << "ERROR: main bucket[" << main_idx << "] cuckoo insertion failed after reaching the maximum eviction count!" << std::endl;
                std::cerr << "  First 16 bytes of the element: ";
                for (size_t i = 0; i < std::min(current_item.pir_key.size(), size_t(16)); ++i) {
                    std::cerr << std::hex << std::setw(2) << std::setfill('0') << (int)current_item.pir_key[i];
                }
                std::cerr << std::dec << std::endl;
                
                double load = static_cast<double>(unique_elements.size()) / (sub_bucket_capacity * nh);
                std::cerr << "  Current bucket load: " << (load * 100) << "%" << std::endl;
                
                bucket_success = false;
                break; // A single failed insertion causes the entire bucket construction to fail.
            }
        }
        
        if (!bucket_success) {
            any_inner_failure.store(true, std::memory_order_relaxed);
            failed_main_idx.store(main_idx, std::memory_order_relaxed);
        }
    }

    if (any_inner_failure.load()) {
        throw std::runtime_error(
            "Sender inner cuckoo hashing failed: main bucket[" + std::to_string(failed_main_idx.load()) +
            "] exceeded the maximum insertion retries; sub_capacity=" + std::to_string(sub_bucket_capacity) +
            " is insufficient. Increase capacity and retry.");
    }

    std::cout << "Sender: sub-bucket construction complete; total sub-buckets = " << (X_star.size() * nh) << std::endl;
    std::cout << "Sender: sub-bucket timing breakdown"
              << " [total " << std::fixed << std::setprecision(1)
              << ((omp_get_wtime() - total_start) * 1000.0) << " ms]" << std::endl;
}

// Phase 3: Prepare the PIR database with one independent row per sub-bucket.
void LPSISender::prepare_pir_database() {
    double total_start = omp_get_wtime();

    if (X_sub_star.empty() || X_sub_star[0].empty() || X_sub_star[0][0].empty()) {
        flattened_database.clear();
        std::cout << "Sender: PIR database preparation complete" << std::endl;
        std::cout << "  PIR database expansion relative to the original dataset X: x0" << std::endl;
        return;
    }

    size_t nh = X_sub_star[0].size();
    size_t sub_bucket_capacity = X_sub_star[0][0].size();
    size_t total_slots = X_sub_star.size() * nh * sub_bucket_capacity;
    flattened_database.clear();
    flattened_database.resize(total_slots);

    uint64_t non_empty = 0;

    // Flatten by sub-bucket, using one row per sub-bucket.
    #pragma omp parallel for num_threads(get_thread_count()) schedule(static) reduction(+:non_empty)
    for (size_t main_idx = 0; main_idx < X_sub_star.size(); ++main_idx) {
        const auto& main_bucket = X_sub_star[main_idx];
        for (size_t sub_idx = 0; sub_idx < main_bucket.size(); ++sub_idx) {
            const auto& sub_bucket = main_bucket[sub_idx];
            size_t base = (main_idx * nh + sub_idx) * sub_bucket_capacity;
            for (size_t slot_idx = 0; slot_idx < sub_bucket.size(); ++slot_idx) {
                const auto& slot = sub_bucket[slot_idx];
                if (!slot.pir_key.empty()) {
                    non_empty++;
                }
                flattened_database[base + slot_idx] = slot;
            }
        }
    }
    
    std::cout << "Sender: PIR database preparation complete" << std::endl;
    // PIR database expansion relative to the original sender set size.
    double inflation = static_cast<double>(flattened_database.size()) / static_cast<double>(input_data.size());
    std::cout << "  PIR database expansion relative to the original dataset X: x" << inflation << std::endl;
    std::cout << "Sender: PIR database preparation timing breakdown"
              << " [nonempty " << non_empty
              << ", total " << std::fixed << std::setprecision(1)
              << ((omp_get_wtime() - total_start) * 1000.0) << " ms]" << std::endl;
}

// Convert the PIR database to bytes.
std::vector<Element> LPSISender::get_pir_database_as_bytes(size_t& num_items, size_t& item_size) {
    num_items = flattened_database.size();
    item_size = LPSIConfig::PIR_PAYLOAD_SIZE;  // Use the configured values.
    
    std::vector<Element> result(num_items);
    
    uint64_t non_empty_count = 0;
    #pragma omp parallel for num_threads(get_thread_count()) schedule(static) reduction(+:non_empty_count)
    for (size_t idx = 0; idx < flattened_database.size(); ++idx) {
        const auto& data = flattened_database[idx];
        Element item(item_size, 0);
        
        bool is_empty_slot = data.pir_key.empty() && data.masked_value.empty();
        
        if (is_empty_slot) {
            // Fill empty slots with nonzero dummy data to avoid transparent PIR ciphertexts.
            // Use a fixed pattern to avoid nondeterministic behavior from random padding.
            for (size_t i = 0; i < item_size; ++i) {
                item[i] = static_cast<unsigned char>((i + 1) % 256);
            }
        } else {
            // First 32 bytes: bucket-bound PIR key.
            if (!data.pir_key.empty()) {
                size_t copy_len = std::min(data.pir_key.size(), size_t(32));
                std::copy(data.pir_key.begin(), data.pir_key.begin() + copy_len, item.begin());
                non_empty_count++;
            }
            
            // Next 96 bytes: masked_value, expanded from 32 bytes to accommodate larger data.
            if (!data.masked_value.empty()) {
                size_t max_masked_size = item_size - 32;  // Remaining space.
                size_t copy_len = std::min(data.masked_value.size(), max_masked_size);
                std::copy(data.masked_value.begin(), data.masked_value.begin() + copy_len, 
                         item.begin() + 32);
                
                // Warn if masked_value exceeds the available space.
                if (data.masked_value.size() > max_masked_size) {
                    std::cerr << "Warning: masked_value size (" << data.masked_value.size() 
                              << ") exceeds the available space (" << max_masked_size << "); data is truncated." << std::endl;
                }
            }
        }
        
        result[idx] = std::move(item);
    }
    
    // Validation: print information for the first three nonempty entries.
    int shown = 0;
    for (size_t i = 0; i < result.size() && shown < 3; ++i) {
        bool is_empty = true;
        for (size_t b = 0; b < 32; ++b) {
            if (result[i][b] != 0) {
                is_empty = false;
                break;
            }
        }
        // Silent mode: do not display hash values in the terminal.
        if (!is_empty) {
            shown++;
        }
    }
    
    return result;
}

void LPSISender::cx_set_encodings(const ElementVector& points, const ElementVector& private_scalars) {
    if(private_scalars.size()!=points.size())throw std::runtime_error("private scalar cache size");
    for(const auto& scalar:private_scalars)if(scalar.size()!=32)throw std::runtime_error("private scalar length");
    for(auto& scalar:private_encoding_scalars)OPENSSL_cleanse(scalar.data(),scalar.size());
    private_encoding_scalars=private_scalars;
    if (points.size() != input_data.size()) throw std::runtime_error("CX sender size mismatch");
    H_x_rs_bytes = points; X_prime.resize(points.size());
    for (size_t i=0;i<points.size();++i) X_prime[i]=hash_H1(points[i]);
}
