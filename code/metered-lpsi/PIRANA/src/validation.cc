#include "validation.h"
#include "utils.h"
#include <stdexcept>
using namespace seal;
using namespace std;

void test_batch_pir_correctness(Server &server,
                                std::vector<std::vector<uint64_t>> &answer,
                                std::vector<uint32_t> &query,
                                PirParms &pir_parms) {
  auto table = pir_parms.get_cuckoo_table();
  for (auto &q : query) {
    auto real_item = server.get_plain_response(q);
    // std::cout << " Real item size: " << real_item.size() << std::endl;
    kuku::QueryResult res = table->query(kuku::make_item(0, q));
    auto loc = res.location();
    if (pir_parms.get_is_compress() == false) {
      auto N = pir_parms.get_seal_parms().poly_modulus_degree();
      auto num_ct = pir_parms.get_num_payload_slot();
      auto bundle_size = pir_parms.get_bundle_size();
      for (uint32_t i = 0; i < num_ct; i++) {
        auto slot_index = loc % N;
        auto bundle_index = loc / N;

        // Assertions are disabled in the release build, so check explicitly.
        // assert(real_item.at(i) ==
        //        answer.at(bundle_size * i + bundle_index).at(slot_index));
        
        uint64_t expected = real_item.at(i);
        uint64_t actual = answer.at(bundle_size * i + bundle_index).at(slot_index);
        
        if (expected != actual) {
            // Print detailed diagnostics for debugging.
            std::cerr << "!!! PIR validation failed (fatal error) !!!" << std::endl;
            std::cerr << "Query Index: " << q << std::endl;
            std::cerr << "Slot: " << i << std::endl;
            std::cerr << "Expected value: " << expected << std::endl;
            std::cerr << "Actual value: " << actual << std::endl;
            
            // Abort by throwing a runtime error.
            throw std::runtime_error("PIR Verification Failed!"); 
        }
      }
    } else {
      auto num_slot = pir_parms.get_num_slot();
      for (uint32_t i = 0, slot = 0, ct_index = 0; i < real_item.size();
           i++, slot++) {
        if (slot == num_slot) {
          slot = 0;
          ct_index++;
        }
        // assert(real_item.at(i) ==
        //        answer.at(ct_index).at(slot + loc * num_slot));
        uint64_t expected = real_item.at(i);
        uint64_t actual = answer.at(ct_index).at(slot + loc * num_slot);
        
        if (expected != actual) {
            std::cerr << "!!! PIR validation failed in compressed mode !!!" << std::endl;
            std::cerr << "Query: " << q << ", Index: " << i << std::endl;
            throw std::runtime_error("PIR Verification Failed (Compressed mode)!");
        }
      }
    }
  }
}

// ==========================================
// Helper: validate PIR results in direct mode.
// ==========================================
void test_direct_batch_pir_correctness(Server &server,
                                       std::vector<std::vector<uint64_t>> &answer,
                                       const std::vector<uint32_t> &query_indices,
                                       PirParms &pir_parms) {
    size_t mismatch_count = 0;
    auto report_mismatch = [&](size_t query_id,
                               uint32_t global_idx,
                               uint32_t payload_slot,
                               uint64_t expected,
                               uint64_t actual,
                               const std::string& mode) {
        if (mismatch_count < 8) {
            std::cerr << "[Direct PIR validation failed] mode=" << mode
                      << ", query#" << query_id
                      << ", global_idx=" << global_idx
                      << ", payload_slot=" << payload_slot
                      << ", expected=" << expected
                      << ", actual=" << actual << std::endl;
        }
        mismatch_count++;
    };

    bool is_compress = pir_parms.get_is_compress();
    auto num_slot = pir_parms.get_num_slot(); 
    
    for (size_t i = 0; i < query_indices.size(); ++i) {
        uint32_t global_idx = query_indices[i];
        auto real_item = server.get_plain_response(global_idx);
        uint32_t loc = i; 

        if (!is_compress) {
            auto N = pir_parms.get_seal_parms().poly_modulus_degree();
            auto num_ct = pir_parms.get_num_payload_slot();
            auto bundle_size = pir_parms.get_bundle_size();

            for (uint32_t j = 0; j < num_ct; j++) {
                uint64_t slot_pos = loc * num_slot; 
                auto slot_index = slot_pos % N;
                auto bundle_index = slot_pos / N;
                uint64_t actual = answer.at(bundle_size * j + bundle_index).at(slot_index);
                uint64_t expected = real_item.at(j);
                
                if (expected != actual) {
                    report_mismatch(i, global_idx, j, expected, actual, "plain");
                }
            }
        } else {
            for (uint32_t j = 0, slot = 0, ct_index = 0; j < real_item.size(); j++, slot++) {
                if (slot == num_slot) {
                    slot = 0;
                    ct_index++;
                }
                
                uint64_t expected = real_item.at(j);
                uint64_t actual = answer.at(ct_index).at(slot + loc * num_slot);
                
                if (expected != actual) {
                    report_mismatch(i, global_idx, j, expected, actual, "compress");
                }
            }
        }
    }

    if (mismatch_count != 0) {
        throw std::runtime_error("Direct PIR verification failed");
    }
    std::cout << "Inner Direct PIR correctness check passed!" << std::endl;
}
