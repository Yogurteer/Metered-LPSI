#include "cx_delivery.h"
#include <unordered_map>
#include <unordered_set>
#include <limits>
#include "cx_oprf.h"
#include <set>
#include "sender.h"
#include "receiver.h"
#include "config.h"

#include "common.h"
#include "client.h"
#include "server.h"
#include "pir_parms.h"
#include "hmain.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <algorithm>
#include <cstdlib>
#include <getopt.h> // Command-line argument parsing.
#include <memory>
#include <stdexcept>

using namespace std;
using namespace std::chrono;

// Global thread count controlled by -t.
int g_thread_count = 1;
static size_t cx_requested_tau=std::numeric_limits<size_t>::max();
// The -t option controls all computational stages.

// Updated batch PIR interface.
std::vector<Element> run_batch_pir(
    const std::vector<Element>& database_items,
    const std::vector<uint32_t>& query_indices,
    size_t num_rows,
    size_t row_size,
    size_t payload_size,
    double &online_time,
    std::string batch_PIR_mode,
    size_t& com_bytes,
    size_t& offline_com_bytes) {
    
    std::vector<Element> results;
    
    uint64_t num_payloads = database_items.size();
    uint64_t num_query = query_indices.size();
    
    bool is_batch = true;
    bool is_compress = false; 
    
    // Obtain the correct plain_modulus_bit and num_payload_slot.
    // num_query is the number of PIR matrix rows (sub-buckets).
    // row_size is the number of PIR matrix columns (sub-bucket capacity).
    std::unique_ptr<PirParms> temp_pir_parms;
    if (batch_PIR_mode == "direct") {
        std::cout << "Constructing direct-mode PirParms for parameter preprocessing..." << std::endl;
        temp_pir_parms = std::make_unique<PirParms>(num_payloads, payload_size, num_query, row_size);
    }
    else if (batch_PIR_mode == "default") {
        std::cout << "Constructing default-mode PirParms for parameter preprocessing..." << std::endl;
        temp_pir_parms = std::make_unique<PirParms>(num_payloads, payload_size, num_query, is_batch, is_compress);
    } else {
        throw std::runtime_error("Unknown batch PIR mode: " + batch_PIR_mode);
    }

    auto plain_modulus_bit = temp_pir_parms->get_seal_parms().plain_modulus().bit_count();
    auto expected_num_payload_slot = temp_pir_parms->get_num_payload_slot();
    

    // Convert an Element byte vector into a uint64_t vector.
    std::vector<std::vector<uint64_t>> input_db(num_payloads);
    // Resize all rows before filling them in parallel.
    for (size_t i = 0; i < num_payloads; ++i) {
        input_db[i].resize(expected_num_payload_slot, 0);
    }

    // Prepare input_db using temp_pir_parms, parallelizing the outer loop.
    #pragma omp parallel for num_threads(g_thread_count) schedule(static)
    for (size_t i = 0; i < num_payloads; ++i) {
        const auto& elem = database_items[i];

        if (elem.size() != payload_size) {
            // Do not throw inside the parallel region; skip with continue. Sizes are validated outside.
            continue;
        }

        size_t bits_per_slot = plain_modulus_bit - 1;
        size_t bit_offset = 0;

        for (size_t slot_idx = 0; slot_idx < expected_num_payload_slot; slot_idx++) {
            uint64_t slot_value = 0;
            size_t bits_in_this_slot = std::min(bits_per_slot, payload_size * 8 - bit_offset);

            for (size_t bit = 0; bit < bits_in_this_slot; bit++) {
                size_t byte_idx = (bit_offset + bit) / 8;
                size_t bit_in_byte = (bit_offset + bit) % 8;

                if (byte_idx < elem.size()) {
                    uint64_t bit_value = (elem[byte_idx] >> bit_in_byte) & 1;
                    slot_value |= (bit_value << bit);
                }
            }

            input_db[i][slot_idx] = slot_value;
            bit_offset += bits_per_slot;
        }
    }
    

    if(batch_PIR_mode == "direct")
    {
        results = my_direct_batch_pir_main(num_payloads, payload_size, num_query, is_batch,
                             is_compress, input_db, query_indices, row_size, online_time, com_bytes, offline_com_bytes);
    }
    else // default mode
    {
        results = my_batch_pir_main(num_payloads, payload_size, num_query, is_batch,
                       is_compress, input_db, query_indices, online_time, com_bytes, offline_com_bytes);
    }
                   
    return results;
}

// Phase 0: Initialize input data from a file.
void phase0_initialize_data(
    LPSISender& sender,
    LPSIReceiver& receiver,
    std::vector<std::pair<std::string, std::string>>& sender_raw_data,
    std::vector<std::string>& receiver_raw_data,
    size_t sender_size,      
    size_t receiver_size,
    const std::string& dataset_path // Additional parameter.
) {
    auto string_to_element = [](const std::string& str) -> Element {
        return Element(str.begin(), str.end());
    };

    std::ifstream file(dataset_path);
    if (!file.is_open()) {
        std::cerr << "Fatal error: cannot open dataset file " << dataset_path << std::endl;
        exit(1);
    }
    
    std::string line;
    
    // 1. Read and skip the sender header.
    // Format: "db size {sz} label bytes {bc} item bytes {bc}".
    if (!std::getline(file, line)) {
        std::cerr << "Error: invalid file format (missing sender header)." << std::endl;
        exit(1);
    }
    
    // 2. Read sender data.
    sender_raw_data.clear();
    sender_raw_data.reserve(sender_size);
    std::vector<std::pair<Element, Element>> sender_data_elements;
    sender_data_elements.reserve(sender_size);
    
    for (size_t i = 0; i < sender_size; ++i) {
        if (!std::getline(file, line)) {
            std::cerr << "Error: insufficient sender data; expected " << sender_size << " rows, stopped at row " << i << "." << std::endl;
            exit(1);
        }
        
        // Format: item,label.
        std::string item, label;
        size_t comma_pos = line.find(',');
        if (comma_pos != std::string::npos) {
            item = line.substr(0, comma_pos);
            label = line.substr(comma_pos + 1);
        } else {
            // Without a comma, treat the entire line as the item; the label may be absent or the format invalid.
            item = line;
            label = ""; 
        }
        
        // Remove any Windows carriage return.
        if (!item.empty() && item.back() == '\r') item.pop_back();
        if (!label.empty() && label.back() == '\r') label.pop_back();

        sender_raw_data.push_back({item, label});
        sender_data_elements.push_back({
            string_to_element(item),
            Element(label.begin(), label.end())
        });
    }
    
    // 3. Read and skip the receiver header.
    // Format: "query size {sz} intersection size {sz} item bytes {bc}".
    if (!std::getline(file, line)) {
        std::cerr << "Error: invalid file format (missing receiver header)." << std::endl;
        exit(1);
    }
    
    // 4. Read receiver data.
    receiver_raw_data.clear();
    receiver_raw_data.reserve(receiver_size);
    ElementVector receiver_data_elements;
    receiver_data_elements.reserve(receiver_size);
    
    for (size_t i = 0; i < receiver_size; ++i) {
        if (!std::getline(file, line)) {
            std::cerr << "Error: insufficient receiver data; expected " << receiver_size << " rows, stopped at row " << i << "." << std::endl;
            exit(1);
        }
        
        std::string item = line;
        if (!item.empty() && item.back() == '\r') item.pop_back(); // Remove \r.
        
        receiver_raw_data.push_back(item);
        receiver_data_elements.push_back(string_to_element(item));
    }
    
    file.close();
    
    // Supply the data to the protocol roles.
    sender.set_input(sender_data_elements);
    receiver.set_input(receiver_data_elements);
}

// Phase 1: VOLE-backed shuffled encoding (SH-DOPRF construction).
static size_t cx_oprf_offline_bytes = 0;
void phase1_shuffled_encoding(LPSISender& sender,LPSIReceiver& receiver,double& online,double& offline,size_t& com) {
    auto result=cx::shuffled_encoding(receiver.cx_input(),sender.get_r_s());
    auto decode_start=std::chrono::steady_clock::now();
    receiver.cx_set_encodings(result.points);
    double finalize_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-decode_start).count();
    online=result.stats.online_ms+finalize_ms;offline=result.stats.offline_ms;com=result.stats.online_bytes;
    cx_oprf_offline_bytes=result.stats.offline_bytes;
    std::vector<cx::Bytes> server_inputs;
    for(const auto& pair:sender.cx_input())server_inputs.push_back(pair.first);
    auto start=std::chrono::steady_clock::now();
    ElementVector private_scalars;
    auto database_points=cx::encode_database(server_inputs,result.server_key,sender.get_r_s(),get_thread_count(),&private_scalars);
    sender.cx_set_encodings(database_points,private_scalars);
    for(auto& scalar:private_scalars)OPENSSL_cleanse(scalar.data(),scalar.size());
    double db_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-start).count();
    offline+=db_ms;
    cx::print_stats(result.stats,receiver.cx_input().size());
    std::cout << "CX_DB_ENCODING_MS " << db_ms << std::endl;
}

// Phase 2: Build hash buckets.
void phase2_build_hash_buckets(
    LPSISender& sender,
    LPSIReceiver& receiver,
    size_t sender_data_size,
    size_t receiver_data_size,
    double& receiver_gen_idx_time,
    double& sender_gen_idx_time,
    double& sender_bucket_oprf_time) {
    
    MyTimer timer;
    
    // Adapt the main bucket count B and the inner hash count nh_inner.
    // Target: bundle_size = ceil(B*nh/N) <= 2 for N=8192, so B*nh <= 16384.
    // Keep nh=3 and reduce B; retaining three choices avoids two-way cuckoo cycles.
    // For very small receiver sets, particularly sizes 1/64/128/256 in the receiver sweep,
    // a small B produces wide rows and large col_size, increasing the direct KPIR encoding dimension.
    // This is slow and may enter unstable parameter ranges. Instead, fill a single 4096-row bundle:
    // keep num_query = B * nh as close to 4096 as possible without exceeding it.
    // This substantially reduces col_size while retaining a single bundle.
    constexpr size_t PIR_N_MAX = 8192;
    constexpr size_t PIR_MAX_BUNDLE = 2;   // Target upper bound for bundle_size.
    constexpr size_t PIR_MAX_QUERY = PIR_N_MAX * PIR_MAX_BUNDLE; // 16384
    constexpr size_t MIN_MAIN_BUCKETS = 64; // Avoid too few buckets and overly wide PIR rows for small receiver sets.
    constexpr size_t MIN_STABLE_QUERY_ROWS = 576;
    constexpr size_t DIRECT_ONE_BUNDLE_QUERY = 4096;
    constexpr size_t SMALL_RECEIVER_PERF_THRESHOLD = 256;

    int adaptive_nh = LPSIConfig::NUM_SUB_BUCKETS; // Keep the hash count fixed at 3.

    // Compute B satisfying B*nh <= PIR_MAX_QUERY, rounding down.
    size_t num_main_buckets;
    {
        size_t B_default = static_cast<size_t>(
            std::ceil(LPSIConfig::MAIN_BUCKET_FACTOR * receiver_data_size));
        size_t B_floor = std::min(PIR_MAX_QUERY / static_cast<size_t>(adaptive_nh),
                                  MIN_MAIN_BUCKETS);
        size_t B_stable_floor = std::min(
            PIR_MAX_QUERY / static_cast<size_t>(adaptive_nh),
            (MIN_STABLE_QUERY_ROWS + static_cast<size_t>(adaptive_nh) - 1) /
                static_cast<size_t>(adaptive_nh));
        size_t B_single_bundle_floor = std::min(
            DIRECT_ONE_BUNDLE_QUERY / static_cast<size_t>(adaptive_nh),
            PIR_MAX_QUERY / static_cast<size_t>(adaptive_nh));
        B_default = std::max(B_default, B_floor);
        B_default = std::max(B_default, B_stable_floor);
        if (receiver_data_size <= SMALL_RECEIVER_PERF_THRESHOLD) {
            B_default = std::max(B_default, B_single_bundle_floor);
        }
        if (B_default * (size_t)adaptive_nh <= PIR_MAX_QUERY) {
            // Use the default B if it already satisfies the constraint.
            num_main_buckets = B_default;
        } else {
            // Reduce B to floor(PIR_MAX_QUERY / nh), but never below receiver_data_size.
            num_main_buckets = PIR_MAX_QUERY / (size_t)adaptive_nh;
            num_main_buckets = std::max(num_main_buckets, receiver_data_size);
        }
    }

    cout << "Outer main-bucket expansion factor: " << LPSIConfig::MAIN_BUCKET_FACTOR << std::endl;

    // Build database indices; automatically increase B and retry on failure.
    // Increase by 5% of receiver_size per attempt, capped at PIR_MAX_QUERY/nh to keep bundle_size <= 2.
    size_t B_ceil = PIR_MAX_QUERY / (size_t)adaptive_nh;
    const size_t B_step = std::max((size_t)1, receiver_data_size / 20); // Approximately 5% per increment.

    // Retry inner cuckoo hashing with fresh seeds before increasing B after repeated failures.
    constexpr int MAX_INNER_RETRY = 10;

    bool build_ok = false;
    while (!build_ok) {
        cout << "[Adaptive] B=" << num_main_buckets
             << ", nh_inner=" << adaptive_nh
             << ", num_query=" << (num_main_buckets * (size_t)adaptive_nh)
             << ", bundle_size=" << (num_main_buckets * (size_t)adaptive_nh + PIR_N_MAX - 1) / PIR_N_MAX
             << std::endl;

        double sender_outer_time = 0.0;
        double receiver_outer_time = 0.0;

        try {
            // Outer hashing: the receiver uses cuckoo hashing, which may fail; the sender uses simple hashing.
            timer.reset();
            sender.build_hash_buckets(num_main_buckets, LPSIConfig::OUTER_NUM_HASH_FUNCTIONS);
            sender_outer_time = timer.elapsed();

            timer.reset();
            receiver.build_hash_buckets(num_main_buckets, LPSIConfig::OUTER_NUM_HASH_FUNCTIONS);
            receiver_outer_time = timer.elapsed();

        } catch (const std::runtime_error& e) {
            // Only the receiver's outer cuckoo hashing can fail; increase B and retry.
            std::cerr << "[Outer cuckoo hashing failed] " << e.what() << std::endl;
            if (num_main_buckets >= B_ceil) {
                throw std::runtime_error("Outer cuckoo hashing failed at the maximum permitted B; the protocol cannot continue.");
            }
            num_main_buckets = std::min(num_main_buckets + B_step, B_ceil);
            std::cerr << "[Retry] Increase B to " << num_main_buckets << " and retry..." << std::endl;
            continue;
        }

        // Inner hashing may fail due to random eviction paths; retry with fresh seeds before increasing B.
        bool inner_ok = false;
        for (int inner_try = 0; inner_try < MAX_INNER_RETRY && !inner_ok; ++inner_try) {
            try {
                timer.reset();
                sender.prepare_bucket_bound_entries();
                double sender_bucket_bound_time = timer.elapsed();

                timer.reset();
                sender.build_sub_buckets(sender_data_size, num_main_buckets, adaptive_nh);
                double sender_inner_time = timer.elapsed();

                timer.reset();
                receiver.build_sub_buckets(sender_data_size, num_main_buckets, adaptive_nh);
                double receiver_inner_time = timer.elapsed();

                sender_gen_idx_time = sender_outer_time + sender_inner_time;
                sender_bucket_oprf_time += sender_bucket_bound_time;
                receiver_gen_idx_time = receiver_outer_time + receiver_inner_time;
                inner_ok = true;
            } catch (const std::runtime_error& inner_e) {
                std::cerr << "[Inner cuckoo hashing failed] " << inner_e.what()
                          << "\n  Retrying with a fresh random seed (" << (inner_try + 1) << "/" << MAX_INNER_RETRY << ")..." << std::endl;
            }
        }

        if (!inner_ok) {
            if (num_main_buckets >= B_ceil) {
                throw std::runtime_error("Inner cuckoo hashing repeatedly failed at the maximum permitted B; the protocol cannot continue.");
            }
            num_main_buckets = std::min(num_main_buckets + B_step, B_ceil);
            std::cerr << "[Increase B] Inner cuckoo hashing repeatedly failed; increase B to " << num_main_buckets << " and retry..." << std::endl;
            continue;
        }

        build_ok = true;
    }
    
}

void phase25_bucket_bound_oprf(
    LPSISender& sender,
    LPSIReceiver& receiver,
    double& online_time,
    size_t& com_bytes) {
    MyTimer timer;


    timer.reset();
    ElementVector step1_output = receiver.compute_bucket_bound_oprf_step1();
    ElementVector step2_output = sender.process_bucket_oprf_step2(step1_output);
    receiver.process_bucket_bound_oprf_step3(step2_output);
    online_time = timer.elapsed();

    com_bytes = get_payload_size(step1_output) + get_payload_size(step2_output);
    if(com_bytes!=66*sender.get_num_main_buckets())throw std::runtime_error("bucket traffic mismatch");
    std::cout << "BUCKET_OPRF b=" << sender.get_num_main_buckets() << " bytes=" << com_bytes << std::endl;
}

// Phase 3: Prepare the PIR database and queries.
void phase3_prepare_pir(
    LPSISender& sender,
    LPSIReceiver& receiver,
    std::vector<Element>& database,
    std::vector<uint32_t>& queries,
    size_t& pir_db_size,
    size_t& item_size,
    double& offline_pir_prep_time) {
    
    
    // The sender prepares the PIR database.
    MyTimer timer;
    timer.reset();
    sender.prepare_pir_database(); // Print internal statistics such as PIR database expansion.
    offline_pir_prep_time = timer.elapsed();
    
    // The sender provides bucket structure information to the receiver.
    size_t sender_num_main_buckets = sender.get_num_main_buckets();
    auto [sender_nh, sender_sub_capacity] = sender.get_sub_bucket_structure();
    
    // The receiver generates query indices.
    receiver.generate_pir_query_indices(sender_num_main_buckets, sender_nh, sender_sub_capacity);
    
    // Retrieve the database and queries.
    size_t num_items;
    database = sender.get_pir_database_as_bytes(num_items, item_size);
    queries = receiver.get_query_indices_flat();
    
}

// Phase 4: Execute PIR queries.
void phase4_execute_pir(
    LPSIReceiver& receiver,
    LPSISender& sender,
    const std::vector<Element>& database,
    const std::vector<uint32_t>& queries,
    size_t item_size,
    double &online_time,
    std::string batch_PIR_mode,
    size_t& com_bytes,
    size_t& offline_com_bytes) {
    
    // Retrieve the database row and column structure.
    size_t sender_num_main_buckets = sender.get_num_main_buckets();
    auto [sender_nh, sender_sub_capacity] = sender.get_sub_bucket_structure();
    size_t num_rows = sender_num_main_buckets * sender_nh;  // Total rows = main bucket count * sub-bucket count.
    size_t row_size = sender_sub_capacity;  // Row size = sub-bucket capacity.

    std::cout << "---------------Call Batch PIR-----------------------" << std::endl;
    
    std::vector<Element> pir_results = run_batch_pir(database, queries, num_rows, row_size, item_size, online_time, batch_PIR_mode, com_bytes, offline_com_bytes);

    receiver.pir_results = pir_results;
    
}

// Phase 6: Pass RECEIVER_SIZE for validation.
static void cx_verify_output(const LPSISender& sender,const LPSIReceiver& receiver,
    const std::unordered_map<std::string,std::string>& truth,size_t tau) {
    const auto& out=receiver.get_intersection();std::unordered_set<std::string> unique;
    if(out.size()!=tau||sender.get_intersection_size()!=tau)throw std::runtime_error("purchase count mismatch");
    for(const auto& [x,v]:out){std::string key(x.begin(),x.end()),label(v.begin(),v.end());
        auto it=truth.find(key);
        if(it==truth.end()||it->second!=label||!unique.insert(key).second)
            throw std::runtime_error("purchased item/label audit failed");
    }
    std::cout<<"CX_STRICT_CORRECTNESS PASS truth="<<truth.size()<<" purchased="<<tau<<" recovered="<<out.size()<<std::endl;
}

int run_main(size_t sender_size, size_t receiver_size, size_t inter_size,
             size_t item_byte, size_t label_byte,
             std::string batch_PIR_mode, std::string dataset_path) {
    // Compute the PIR payload size dynamically: 32 bytes for x_prime + item_byte + label_byte.
    LPSIConfig::PIR_PAYLOAD_SIZE = 32 + item_byte + label_byte;
    size_t payload_size = label_byte;  // Retained for compatible log output.

    std::cout << "========================================" << std::endl;
    std::cout << "   Payable LPSI protocol (dynamic parameters and phase timings)" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Mode: " << batch_PIR_mode << std::endl;
    std::cout << "Threads: worker=" << g_thread_count
              << ", oprf=" << g_thread_count << std::endl;

    // Create instances with item_byte and label_byte for encoding and decoding.
    LPSISender sender(item_byte, label_byte);
    LPSIReceiver receiver(item_byte, label_byte);
    
    std::vector<std::pair<std::string, std::string>> sender_raw_data;
    std::vector<std::string> receiver_raw_data;

    // [1] Initialization
    std::cout << "\n[1] Importing data and initializing..." << std::endl;
    auto t0_start = high_resolution_clock::now();
    
    // Pass the input size.
    phase0_initialize_data(sender, receiver, sender_raw_data, receiver_raw_data, sender_size, receiver_size, dataset_path);
    std::cout << "[Data import] Sender entries: " << sender_size << std::endl;
    std::cout << "[Data import] Receiver entries: " << receiver_size << std::endl;
    std::cout << "[Data import] Payload size: " << payload_size << " bytes" << std::endl;
    
    auto t0_end = high_resolution_clock::now();
    auto dur_init = duration_cast<milliseconds>(t0_end - t0_start).count();

    // Ground truth is test-harness state only and is never sent to either role.
    // Build it outside protocol timers; audit cost is included only in full process wall time.
    std::unordered_set<std::string> client_set(receiver_raw_data.begin(),receiver_raw_data.end());
    std::unordered_map<std::string,std::string> cx_truth;
    for(const auto& [x,v]:sender_raw_data)if(client_set.count(x))cx_truth.emplace(x,v);
    if(cx_truth.size()!=inter_size)throw std::runtime_error("dataset intersection header mismatch");

    // [2] VOLE-backed shuffled encoding
    std::cout << "\n[2] Running SH-DOPRF / VOLE-based encoding..." << std::endl;
    double receiver_oprf_time = 0.0;
    double oprf_offline_time = 0.0;
    size_t p1_com_bytes = 0;
    phase1_shuffled_encoding(sender, receiver, receiver_oprf_time, oprf_offline_time, p1_com_bytes);
    auto dur_oprf_online = receiver_oprf_time;
    auto dur_oprf_offline = oprf_offline_time;
    const size_t shdoprf_online_bytes = p1_com_bytes;
    cout << "[SH-DOPRF] Communication: " << p1_com_bytes << " Bytes" << std::endl;

    // [3] Hash Buckets
    std::cout << "\n[3] Building the two-level hash structure..." << std::endl;
    double receiver_gen_idx_time = 0.0;
    double sender_gen_idx_time = 0.0;
    double sender_bucket_oprf_prep_time = 0.0;
    
    // Pad receiver_raw_data to a multiple of N.
    size_t original_receiver_size = receiver_raw_data.size();
    PpsiParm gloal_parm;
    size_t N = gloal_parm.poly_degree;
    size_t ratio = (original_receiver_size + N - 1) / N; // Round up.
    size_t pad_receiver_size = ratio * N;
    auto cx_hash_start=std::chrono::steady_clock::now();
    phase2_build_hash_buckets(sender, receiver, sender_raw_data.size(), receiver_raw_data.size(),
                              receiver_gen_idx_time, sender_gen_idx_time,
                              sender_bucket_oprf_prep_time);
    double cx_hash_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-cx_hash_start).count();
    sender_gen_idx_time=cx_hash_ms-receiver_gen_idx_time-sender_bucket_oprf_prep_time;
    if(sender_gen_idx_time < -1)throw std::runtime_error("hash timer reconciliation");
    sender_gen_idx_time=std::max(0.0,sender_gen_idx_time);

    auto online_receiver_genidx_time = receiver_gen_idx_time;
    auto offline_sender_genidx_time = sender_gen_idx_time;

    std::cout << "\n[3.5] Running the second-round OPRF per bucket..." << std::endl;
    double bucket_bound_oprf_online_time = 0.0;
    size_t bucket_bound_oprf_com_bytes = 0;
    phase25_bucket_bound_oprf(sender, receiver, bucket_bound_oprf_online_time,
                              bucket_bound_oprf_com_bytes);
    dur_oprf_online += bucket_bound_oprf_online_time;
    dur_oprf_offline += sender_bucket_oprf_prep_time;
    p1_com_bytes += bucket_bound_oprf_com_bytes;
    std::cout << "[Bucket-bound OPRF] Communication: " << bucket_bound_oprf_com_bytes << " Bytes" << std::endl;

    // ==========================================
    // 4. Batch PIR (Prepare + Execute)
    // ==========================================
    std::cout << "\n[4] Running batch PIR (prepare and execute)..." << std::endl;
    
    std::vector<Element> database;
    std::vector<uint32_t> queries;
    size_t pir_db_size, item_size;
    double offline_pir_prep_time = 0.0;
    double online_pir_process_time = 0.0;

    // Prepare PIR: generate the database and queries.
    phase3_prepare_pir(sender, receiver, database, queries, pir_db_size, item_size, offline_pir_prep_time);

    // Execute PIR cryptographic operations.
    size_t p4_com_bytes = 0;
    size_t p4_offline_com_bytes = 0;
    auto cx_pir_start=std::chrono::steady_clock::now();
    phase4_execute_pir(receiver, sender, database, queries, item_size, online_pir_process_time, batch_PIR_mode, p4_com_bytes, p4_offline_com_bytes);
    double cx_pir_wall_ms=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-cx_pir_start).count();
    if(online_pir_process_time>cx_pir_wall_ms+1)throw std::runtime_error("PIR online timer exceeds measured wall");
    double cx_pir_setup_ms=std::max(0.0,cx_pir_wall_ms-online_pir_process_time);
    offline_pir_prep_time+=cx_pir_setup_ms;

    cout << "[Batch PIR] Online communication: " << p4_com_bytes << " Bytes" << std::endl;
    cout << "[Batch PIR] Offline communication (keys): " << p4_offline_com_bytes << " Bytes" << std::endl;
    
    // // --- Simulated PIR and validation, excluded from timing ---
    
    auto cx_hits_start=std::chrono::steady_clock::now();
    receiver.process_pir_results(receiver.pir_results);
    if(receiver.hit_element_indices.size()!=cx_truth.size())throw std::runtime_error("PIR hit count differs from truth");
    size_t cx_tau=cx_requested_tau==std::numeric_limits<size_t>::max()?cx_truth.size():cx_requested_tau;
    receiver.cx_select_purchases(cx_tau);
    online_pir_process_time+=std::chrono::duration<double,std::milli>(std::chrono::steady_clock::now()-cx_hits_start).count();


    // [5] OPRF Delivery
    std::cout << "\n[5] Running delivery..." << std::endl;
    auto t4_start = high_resolution_clock::now();
    std::vector<Element> bucket_keys;
    size_t len_byte_r = LPSIConfig::BUCKET_KEY_SIZE_BYTES;
    size_t p5_com_bytes = 0;
    size_t p5_offline_com_bytes = 0;

    double delivery_online_time = 0.0;
    double delivery_offline_time = 0.0;
    auto cx_choices=receiver.get_delivery_choices();
    cxdelivery::Stats cx_delivery_stats;
    bucket_keys=cxdelivery::deliver(sender.cx_delivery,cx_choices,g_thread_count,cx_delivery_stats);
    sender.set_intersection_size(cx_tau);
    delivery_online_time=cx_delivery_stats.online_ms;
    delivery_offline_time=sender.cx_delivery.preparation_ms();
    dur_oprf_offline-=delivery_offline_time;
    p5_com_bytes=cx_delivery_stats.wire_bytes;
    const char* cx_backend="Delivery-P256-RFC9497";

    
    auto t4_end = high_resolution_clock::now();
    double cx_step5_wall=duration<double,std::milli>(t4_end-t4_start).count();
    delivery_online_time=std::max(delivery_online_time,cx_step5_wall);

    cout << "[Delivery] Online communication: " << p5_com_bytes << " Bytes" << std::endl;
    cout << "[Delivery] Offline communication (preparation): " << p5_offline_com_bytes << " Bytes" << std::endl;

    // [6] Decrypt
    std::cout << "\n[6] Decrypting and validating..." << std::endl;
    auto t5_start = high_resolution_clock::now();
    // Pass the input size.
    receiver.decrypt_intersection(bucket_keys);
    auto t5_end = high_resolution_clock::now();
    auto dur_decrypt = duration<double,std::milli>(t5_end-t5_start).count();
    cx_verify_output(sender,receiver,cx_truth,cx_tau);


    // ==========================================
    // Reorganized summary output.
    // ==========================================

    // Online: shuffled encoding + bucket OPRF + PIR + Delivery.
    size_t total_online_com  = p1_com_bytes + p4_com_bytes + p5_com_bytes;
    // Offline: SH-DOPRF preprocessing (including real base OTs) + PIR keys.
    size_t total_offline_com = cx_oprf_offline_bytes + p4_offline_com_bytes + p5_offline_com_bytes;

    // Merge Gen_idx into KPIR: receiver bucketing is online; sender bucketing and PIR database preparation are offline.
    double kpir_online_time  = online_receiver_genidx_time + online_pir_process_time;
    double kpir_offline_time = offline_sender_genidx_time + offline_pir_prep_time;

    // Timing summary, with Gen_idx included in KPIR.
    double total_offline_time = dur_oprf_offline + kpir_offline_time + delivery_offline_time;
    double total_online_time  = dur_oprf_online + kpir_online_time + delivery_online_time + dur_decrypt;
    double total_protocol_time = total_offline_time + total_online_time;

    // Column width constants.
    const int LABEL_WIDTH = 40;
    const int TIME_WIDTH  = 12;

    std::cout << "\n========================================" << std::endl;
    std::cout << "        Protocol execution timings" << std::endl;
    std::cout << "========================================" << std::endl;

    std::cout << std::fixed << std::setprecision(2);

    std::cout << std::left << std::setw(LABEL_WIDTH) << "0. Data import (Init):"
              << std::right << std::setw(TIME_WIDTH) << (double)dur_init << " ms" << std::endl;

    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "           Offline phase" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "1. Encoding (offline):"
              << std::right << std::setw(TIME_WIDTH) << dur_oprf_offline << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "2. KPIR setup + sender bucketing (offline):"
              << std::right << std::setw(TIME_WIDTH) << kpir_offline_time << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "3. Delivery preparation (offline):"
              << std::right << std::setw(TIME_WIDTH) << delivery_offline_time << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << ">>> Total offline time:"
              << std::right << std::setw(TIME_WIDTH) << total_offline_time << " ms" << std::endl;

    std::cout << "\n----------------------------------------" << std::endl;
    std::cout << "           Online phase" << std::endl;
    std::cout << "----------------------------------------" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "1. Encoding (online):"
              << std::right << std::setw(TIME_WIDTH) << dur_oprf_online << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "2. KPIR query + receiver bucketing (online):"
              << std::right << std::setw(TIME_WIDTH) << kpir_online_time << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "3. Delivery online (online):"
              << std::right << std::setw(TIME_WIDTH) << delivery_online_time << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << "4. Decryption and validation (online):"
              << std::right << std::setw(TIME_WIDTH) << (double)dur_decrypt << " ms" << std::endl;

    std::cout << std::left << std::setw(LABEL_WIDTH) << ">>> Total online time:"
              << std::right << std::setw(TIME_WIDTH) << total_online_time << " ms" << std::endl;

    std::cout << "\n========================================" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "Total protocol execution time:"
              << std::right << std::setw(TIME_WIDTH) << total_protocol_time << " ms" << std::endl;
    std::cout << "========================================" << std::endl;

    // Communication statistics.
    std::cout << "\n========================================" << std::endl;
    std::cout << "        Protocol communication statistics (MB)" << std::endl;
    std::cout << "========================================" << std::endl;
    auto to_mb = [](size_t b) { return (double)b / (1024.0 * 1024.0); };

    std::cout << "\n--- Online communication ---" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  Encoding (online):"
              << std::right << std::setw(TIME_WIDTH) << to_mb(p1_com_bytes) << " MB" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  KPIR query+response (online):"
              << std::right << std::setw(TIME_WIDTH) << to_mb(p4_com_bytes) << " MB" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  Delivery (online):"
              << std::right << std::setw(TIME_WIDTH) << to_mb(p5_com_bytes) << " MB" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  >>> Total online communication:"
              << std::right << std::setw(TIME_WIDTH) << to_mb(total_online_com) << " MB" << std::endl;

    std::cout << "\n--- Offline communication ---" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  KPIR keys (offline):"
              << std::right << std::setw(TIME_WIDTH) << to_mb(p4_offline_com_bytes) << " MB" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  Delivery preparation (offline):"
              << std::right << std::setw(TIME_WIDTH) << to_mb(p5_offline_com_bytes) << " MB" << std::endl;
    std::cout << std::left << std::setw(LABEL_WIDTH) << "  >>> Total offline communication:"
              << std::right << std::setw(TIME_WIDTH) << to_mb(total_offline_com) << " MB" << std::endl;
    std::cout << "========================================" << std::endl;

    // CSV output.
    // Column definitions:
    // Sender,Receiver,Inter,Label_byte,Item_byte,
    // Encoding_on,KPIR_on,Delivery_on,Sum_online,
    // Encoding_off,KPIR_off,Delivery_off,Sum_offline,
    // Encoding_com_on,KPIR_com_on,Delivery_com_on,Sum_com_on,
    // KPIR_com_off,Delivery_com_off,Sum_com_off
    std::cout << "\n========== CSV Format Output ==========" << std::endl;
    std::cout << "S_size,R_size,I_size,Label_bytes,Item_bytes,"
                 "Encoding_on,KPIR_on,Delivery_on,Sum_online,"
                 "Encoding_off,KPIR_off,Delivery_off,Sum_offline,"
                 "Encoding_com_on,KPIR_com_on,Delivery_com_on,Sum_com_on,"
                 "KPIR_com_off,Delivery_com_off,Sum_com_off" << std::endl;
    std::cout << std::fixed << std::setprecision(9)
              << sender_size << ","
              << receiver_size << ","
              << inter_size << ","
              << payload_size << ","
              << item_byte << ","
              // Online time (s).
              << dur_oprf_online / 1000.0 << ","
              << kpir_online_time / 1000.0 << ","
              << delivery_online_time / 1000.0 << ","
              << total_online_time / 1000.0 << ","
              // Offline time (s).
              << dur_oprf_offline / 1000.0 << ","
              << kpir_offline_time / 1000.0 << ","
              << delivery_offline_time / 1000.0 << ","
              << total_offline_time / 1000.0 << ","
              // Online communication (MB).
              << to_mb(p1_com_bytes) << ","
              << to_mb(p4_com_bytes) << ","
              << to_mb(p5_com_bytes) << ","
              << to_mb(total_online_com) << ","
              // Offline communication (MB).
              << to_mb(p4_offline_com_bytes) << ","
              << to_mb(p5_offline_com_bytes) << ","
              << to_mb(total_offline_com)
              << std::endl;
    std::cout << "=======================================" << std::endl;
    
    std::cout<<"CX_RUN_JSON {\"backend\":\""<<cx_backend<<"\",\"tau\":"<<cx_tau
      <<",\"intersection\":"<<cx_truth.size()<<",\"buckets\":"<<sender.get_num_main_buckets()
      <<",\"delivery_online_bytes\":"<<p5_com_bytes<<",\"delivery_offline_bytes\":"<<p5_offline_com_bytes
      <<",\"shdoprf_offline_bytes\":"<<cx_oprf_offline_bytes<<",\"pir_setup_added_ms\":"<<cx_pir_setup_ms
      <<",\"threads_per_role\":"<<g_thread_count
      <<",\"shdoprf_online_ms\":"<<receiver_oprf_time<<",\"shdoprf_offline_with_database_ms\":"<<oprf_offline_time
      <<",\"shdoprf_online_bytes\":"<<shdoprf_online_bytes
      <<",\"bucket_oprf_online_ms\":"<<bucket_bound_oprf_online_time
      <<",\"bucket_oprf_offline_ms\":"<<(sender_bucket_oprf_prep_time-delivery_offline_time)
      <<",\"bucket_oprf_online_bytes\":"<<bucket_bound_oprf_com_bytes
      <<",\"decrypt_ms\":"<<dur_decrypt<<",\"correct\":true}"<<std::endl;
    return 0;
}

// ==========================================
// Main Entry: Argument Parsing (eg. ./lpsi_test -x 4096 -y 256 -p 1)
// ==========================================
int main(int argc, char** argv) {
    // Default parameters.
    size_t sender_size = 4096;    // Default: 2^12.
    size_t receiver_size = 1024;  // Default: 2^8.
    size_t label_byte = 1;        // -p: label (value) length in bytes; default: 1.
    size_t item_byte  = 16;       // -q: item (key) length in bytes; default: 16.
    size_t is_default_mode = 0;   // Use direct mode by default.
    size_t inter_size = 0;
    std::string dataset_path = "../data/dataset_default.csv"; // Default path.

    int opt;
    while ((opt = getopt(argc, argv, "x:y:i:p:q:t:m:f:u:h")) != -1) {
        switch (opt) {
            case 'u': cx_requested_tau=std::stoull(optarg); break;
            case 'x':
                sender_size = std::stoul(optarg);
                break;
            case 'y':
                receiver_size = std::stoul(optarg);
                break;
            case 'i':
                inter_size = std::stoul(optarg);
                break;
            case 'p':
                label_byte = std::stoul(optarg);  // Label (value) length in bytes.
                break;
            case 'q':
                item_byte = std::stoul(optarg);   // Item (key) length in bytes.
                break;
            case 't':
                g_thread_count = std::stoi(optarg);  // Worker thread count.
                break;
            case 'f': dataset_path = optarg; break;
            case 'm':
                is_default_mode = std::stoul(optarg);
                break;
            case 'h':
                std::cout << "Usage: " << argv[0] << " [options]\n"
                          << "Options:\n"
                          << "  -x <size>   Sender data size (default: 4096)\n"
                          << "  -y <size>   Receiver data size (default: 1024)\n"
                          << "  -i <size>   Intersection size (for logging, default: 0)\n"
                          << "  -p <bytes>  Label (value) byte length (default: 1)\n"
                          << "  -q <bytes>  Item  (key)   byte length (default: 16)\n"
                          << "  -t <num>    Worker thread count (default: 1)\n"
                          << "  -m <mode>   Batch PIR mode: 1-default, 0-direct\n"
                          << "  -f <path>   Dataset CSV file path\n"
                          << "  -h          Show this help message\n";
                return 0;
            default:
                std::cerr << "Unknown option. Use -h for help." << std::endl;
                return 1;
        }
    }

    cx::set_thread_limit(g_thread_count);
    omp_set_dynamic(0);
    omp_set_num_threads(g_thread_count);
    if(g_thread_count<1||g_thread_count>64)throw std::runtime_error("thread limits");
    // Run the main protocol.
    std::string batch_PIR_mode = (is_default_mode == 1) ? "default" : "direct";
    run_main(sender_size, receiver_size, inter_size, item_byte, label_byte, batch_PIR_mode, dataset_path);
    
    return 0;
}
