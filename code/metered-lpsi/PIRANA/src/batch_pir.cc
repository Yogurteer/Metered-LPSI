#include "hmain.h"

namespace {
bool env_flag_enabled_local(const char* name) {
  const char* value = std::getenv(name);
  if (!value) {
    return false;
  }
  std::string flag(value);
  std::transform(flag.begin(), flag.end(), flag.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return flag == "1" || flag == "true" || flag == "yes" || flag == "on";
}
}
#include <iomanip>
#include <omp.h>

extern int g_thread_count;

std::vector<Element> my_batch_pir_main(const uint64_t num_payloads, const uint64_t payload_size,
                    const uint64_t num_query, const bool is_batch,
                    const bool is_compress, std::vector<std::vector<uint64_t>> input_db,
                    std::vector<uint32_t> query_indices, double& online_time, size_t& com_bytes,
                    size_t& offline_com_bytes) {
  std::cout << "Start my batch PIR! " << std::endl;
  Timer timer;
  timer.reset();

  std::vector<Element> results;

  PirParms pir_parms(num_payloads, payload_size, num_query, is_batch,
                     is_compress);
  
  // ===== Data validation and preprocessing =====
  auto plain_modulus = pir_parms.get_seal_parms().plain_modulus().value();
  auto plain_modulus_bit = pir_parms.get_seal_parms().plain_modulus().bit_count();
  auto expected_num_payload_slot = pir_parms.get_num_payload_slot();
  
  // Validate the input database size.
  if (input_db.size() != num_payloads) {
    std::cerr << "Error: input database size (" << input_db.size() 
              << ") does not match num_payloads (" << num_payloads << ")!" << std::endl;
    throw std::runtime_error("Database size mismatch");
  }
  
  // Validate and preprocess each payload.
  bool has_zero_value = false;
  bool has_overflow = false;
  uint64_t max_value_found = 0;
  
  for (size_t i = 0; i < input_db.size(); i++) {
    auto& payload = input_db[i];
    
    // Check the number of slots in the payload.
    if (payload.size() != expected_num_payload_slot) {
      std::cerr << "Error: Payload[" << i << "] has size (" << payload.size() 
                << "), which does not match num_payload_slot (" << expected_num_payload_slot << ")!" << std::endl;
      std::cerr << "Hint: payload_size=" << payload_size << " bytes; each slot stores " 
                << (plain_modulus_bit - 1) << " bits" << std::endl;
      std::cerr << "Formula: num_payload_slot = ceil(payload_size * 8 / (plain_modulus_bit - 1))" << std::endl;
      std::cerr << "         = ceil(" << payload_size << " * 8 / " << (plain_modulus_bit - 1) << ")" << std::endl;
      std::cerr << "         = " << expected_num_payload_slot << std::endl;
      throw std::runtime_error("Payload slot count mismatch");
    }
    
    // Check each value.
    for (size_t j = 0; j < payload.size(); j++) {
      auto& value = payload[j];
      max_value_found = std::max(max_value_found, value);
      
      // Only record zero values; do not replace them.
      // The database comes from the upper protocol layer. Zero is valid; replacing it irreversibly changes the data.
      if (value == 0) {
        has_zero_value = true;
      }
      
      // Check for values outside plain_modulus.
      if (value >= plain_modulus) {
        has_overflow = true;
        std::cerr << "Error: Payload[" << i << "][" << j << "] has value (" << value 
                  << "), which exceeds plain_modulus (" << plain_modulus << ")!" << std::endl;
      }
    }
  }
  
  if (has_zero_value) {
    std::cout << "Hint: zero values detected and preserved without replacement." << std::endl;
  }
  
  if (has_overflow) {
    std::cerr << "\nData validation failed: values exceed plain_modulus!" << std::endl;
    std::cerr << "Maximum value: " << max_value_found << ", plain_modulus: " << plain_modulus << std::endl;
    throw std::runtime_error("Data value exceeds plain_modulus constraint");
  }
  
  std::cout << "[PIR parameter preprocessing] Data validation passed! Maximum payload value: " << max_value_found << " <  plain_modulus " << plain_modulus << std::endl;
  // std::cout << "===================================\n" << std::endl;
  
  Client batch_client(pir_parms);
  std::stringstream keys = batch_client.save_keys();
  Server batch_server(pir_parms, is_batch, false, input_db);

  batch_server.set_keys(keys);
  offline_com_bytes = keys.str().size();
  auto init_time = timer.elapsed();

  timer.reset();

  // random generate query
  
  std::vector<uint32_t> batch_query_index(num_query);
  batch_query_index = query_indices;
  // for (auto &q : batch_query_index) {
  //   q = rand() % num_payloads;
  // }
  std::stringstream query = batch_client.gen_batch_query(batch_query_index);
  auto query_time = timer.elapsed();

  timer.reset();
  std::stringstream response = batch_server.gen_batch_response(query);
  auto response_time = timer.elapsed();

  timer.reset();
  std::vector<std::vector<uint64_t>> answer =
      batch_client.extract_batch_answer(response);
  auto extract_time = timer.elapsed();

  test_batch_pir_correctness(batch_server, answer, batch_query_index,
                             pir_parms);
  std::cout << "\n[Internal PIR validation] PIR correctness check passed!" << std::endl;
  
  // Helper: extract the payload slots for one query from answer.
  auto extract_payload_slots = [&](size_t q_idx, uint32_t query_index) -> std::vector<uint64_t> {
    auto table = pir_parms.get_cuckoo_table();
    kuku::QueryResult res = table->query(kuku::make_item(0, query_index));
    auto loc = res.location();
    
    std::vector<uint64_t> real_item;
    
    if (pir_parms.get_is_compress() == false) {
      auto N = pir_parms.get_seal_parms().poly_modulus_degree();
      auto num_ct = pir_parms.get_num_payload_slot();
      auto bundle_size = pir_parms.get_bundle_size();
      real_item.resize(num_ct);
      
      for (uint32_t i = 0; i < num_ct; i++) {
        auto slot_index = loc % N;
        auto bundle_index = loc / N;
        real_item[i] = answer.at(bundle_size * i + bundle_index).at(slot_index);
      }
    } else {
      auto num_slot = pir_parms.get_num_slot();
      auto num_payload_slot = pir_parms.get_num_payload_slot();
      real_item.resize(num_payload_slot);
      
      for (uint32_t i = 0, slot = 0, ct_index = 0; i < num_payload_slot; i++, slot++) {
        if (slot == num_slot) {
          slot = 0;
          ct_index++;
        }
        real_item[i] = answer.at(ct_index).at(slot + loc * num_slot);
      }
    }
    
    return real_item;
  };
  
  // Helper: convert payload slots back to the original byte array.
  auto slots_to_bytes = [&](const std::vector<uint64_t>& slots) -> Element {
    auto plain_modulus_bit = pir_parms.get_seal_parms().plain_modulus().bit_count();
    size_t bits_per_slot = plain_modulus_bit - 1;
    
    // Obtain the internal PIR payload_size.
    auto pir_payload_size = pir_parms.get_payload_size();
    
    // Use the internal PIR payload_size.
    Element result(pir_payload_size, 0);
    size_t bit_offset = 0;
    
    for (size_t slot_idx = 0; slot_idx < slots.size(); slot_idx++) {
      uint64_t slot_value = slots[slot_idx];
      
      size_t bits_in_this_slot = std::min(bits_per_slot, pir_payload_size * 8 - bit_offset);
      
      // Write the low bits_in_this_slot bits of slot_value back to the byte array.
      for (size_t bit = 0; bit < bits_in_this_slot; bit++) {
        size_t byte_idx = (bit_offset + bit) / 8;
        size_t bit_in_byte = (bit_offset + bit) % 8;
        
        if (byte_idx < pir_payload_size) {
          uint8_t bit_value = (slot_value >> bit) & 1;
          result[byte_idx] |= (bit_value << bit_in_byte);
        }
      }
      
      // Mirror the encoding step by advancing bits_per_slot each time.
      bit_offset += bits_per_slot;
    }
    
    return result;
  };
  
  timer.reset();
  // Extract each query's payload from answer into results.
  results.resize(num_query);
  
  for (size_t q_idx = 0; q_idx < batch_query_index.size(); q_idx++) {
    auto q = batch_query_index[q_idx];
    
    // Extract payload slots; each slot stores part of the bit sequence.
    std::vector<uint64_t> payload_slots = extract_payload_slots(q_idx, q);
    
    // Reassemble the slots into the original byte array.
    results[q_idx] = slots_to_bytes(payload_slots);
  }
  auto result_convert_time = timer.elapsed();

  std::cout << "------------------------------------" << std::endl;
  std::cout << "Performance(Default Mode): " << std::endl;
  std::cout << "Init time: " << init_time << " ms " << std::endl;
  std::cout << "Gen query time: " << query_time << " ms " << std::endl;
  std::cout << "Gen response time: " << response_time << " ms " << std::endl;
  std::cout << "Extract answer time: " << extract_time << " ms "
            << std::endl;
  std::cout << "Result convert time: " << result_convert_time << " ms "
            << std::endl;

  online_time = query_time + response_time + extract_time + result_convert_time;
  std::cout << "Batch PIR online time: " << online_time << " ms " << std::endl;

  std::cout << "Query size: " << query.str().size() / 1024.0 << " KBytes"
            << std::endl;

  std::cout << "Response size: " << response.str().size() / 1024.0 << " KBytes"
            << std::endl;
  
  com_bytes = query.str().size() + response.str().size();
  
  return results;
}

// ==========================================
// Main entry point for direct batch PIR.
// ==========================================
std::vector<Element> my_direct_batch_pir_main(
    const uint64_t num_payloads,
    const uint64_t payload_size,
    const uint64_t num_query,
    const bool is_batch,
    const bool is_compress,
    std::vector<std::vector<uint64_t>> input_db,
    std::vector<uint32_t> query_indices,
    uint64_t col_size,
    double& online_time,
    size_t& com_bytes,
    size_t& offline_com_bytes) {

  std::cout << "Start Direct Batch PIR (Skip Cuckoo)! " << std::endl;
  Timer timer;
  timer.reset();

  // 1. Initialize parameters for direct mode.
  uint64_t num_rows = query_indices.size(); 
  
  // Handle padding: the database size must equal num_rows * col_size.
  uint64_t expected_db_size = num_rows * col_size;
  if (input_db.size() < expected_db_size) {
      std::cerr << "Error: Input DB size (" << input_db.size() 
                << ") is smaller than required (" << expected_db_size << ")" << std::endl;
      throw std::runtime_error("Input DB size is too small for Direct PIR!");
  }
  if (input_db.size() > expected_db_size) {
      // Truncate excess padding.
      // std::cout << "[PIR Warning] Truncating DB from " << input_db.size() 
      //           << " to " << expected_db_size << " (removing padding)" << std::endl;
      input_db.resize(expected_db_size);
  }

  // Initialize parameters with the direct-mode constructor.
  PirParms pir_parms(expected_db_size, payload_size, num_rows, col_size);
  pir_parms.print_seal_parms();
  pir_parms.print_pir_parms();
  
  // 2. Initialize the client and server.
  Client batch_client(pir_parms);
  std::stringstream keys = batch_client.save_keys();

  bool random_db = false;
  Server batch_server(pir_parms, true, random_db, input_db);
  batch_server.set_keys(keys);
  offline_com_bytes = keys.str().size();

  auto init_time = timer.elapsed();
  timer.reset();

  // 3. Generate direct queries.
  std::vector<uint32_t> offsets(num_query);
  for(size_t i=0; i<num_query; ++i) {
      offsets[i] = query_indices[i] % col_size;
  }

  std::stringstream query = batch_client.gen_direct_batch_query(offsets);
  auto query_time = timer.elapsed();

  // 4. Generate responses.
  timer.reset();
  std::stringstream response = batch_server.gen_direct_batch_response_no_cuckoo(query);
  auto response_time = timer.elapsed();

  // 5. Extract results as slots.
  timer.reset();
  std::vector<std::vector<uint64_t>> answer = batch_client.extract_direct_batch_answer_no_cuckoo(response);
  auto extract_time = timer.elapsed();

  // 6. Optional debug validation, disabled by default to avoid affecting batch experiment performance.
  if (env_flag_enabled_local("LPSI_DEBUG_VERIFY_DIRECT_PIR")) {
    test_direct_batch_pir_correctness(batch_server, answer, query_indices, pir_parms);
  }

  // 7. Convert results from slots to bytes.
  timer.reset();
  
  // Helper lambda: extract the payload slots for one query.
  auto extract_payload_slots = [&](uint32_t loc) -> std::vector<uint64_t> {
    std::vector<uint64_t> real_item;
    
    if (!pir_parms.get_is_compress()) {
      // ==============================================
      // Uncompressed extraction must match the validation function.
      // ==============================================
      auto N = pir_parms.get_seal_parms().poly_modulus_degree();
      auto num_ct = pir_parms.get_num_payload_slot();
      auto bundle_size = pir_parms.get_bundle_size();
      auto num_slot = pir_parms.get_num_slot(); // This parameter is required.

      real_item.resize(num_ct);
      
      for (uint32_t i = 0; i < num_ct; i++) {
        uint64_t slot_pos = loc * num_slot; // Compute the start of the row.
        auto slot_index = slot_pos % N;
        auto bundle_index = slot_pos / N;
        
        real_item[i] = answer.at(bundle_size * i + bundle_index).at(slot_index);
      }
    } else {
      // Extraction logic for compressed mode.
      auto num_slot = pir_parms.get_num_slot();
      auto num_payload_slot = pir_parms.get_num_payload_slot();
      real_item.resize(num_payload_slot);
      
      for (uint32_t i = 0, slot = 0, ct_index = 0; i < num_payload_slot; i++, slot++) {
        if (slot == num_slot) {
          slot = 0;
          ct_index++;
        }
        real_item[i] = answer.at(ct_index).at(slot + loc * num_slot);
      }
    }
    return real_item;
  };

  // Helper lambda: convert slots to bytes using the same logic.
  auto slots_to_bytes = [&](const std::vector<uint64_t>& slots) -> Element {
    auto plain_modulus_bit = pir_parms.get_seal_parms().plain_modulus().bit_count();
    size_t bits_per_slot = plain_modulus_bit - 1;
    auto pir_payload_size = pir_parms.get_payload_size();
    
    Element result(pir_payload_size, 0);
    size_t bit_offset = 0;
    
    for (size_t slot_idx = 0; slot_idx < slots.size(); slot_idx++) {
      uint64_t slot_value = slots[slot_idx];
      
      size_t bits_in_this_slot = std::min(bits_per_slot, pir_payload_size * 8 - bit_offset);
      
      for (size_t bit = 0; bit < bits_in_this_slot; bit++) {
        size_t byte_idx = (bit_offset + bit) / 8;
        size_t bit_in_byte = (bit_offset + bit) % 8;
        
        if (byte_idx < pir_payload_size) {
          uint8_t bit_value = (slot_value >> bit) & 1;
          result[byte_idx] |= (bit_value << bit_in_byte);
        }
      }
      bit_offset += bits_per_slot;
    }
    return result;
  };

  // Convert all results.
  std::vector<Element> results(num_query);
  #pragma omp parallel for num_threads(g_thread_count) schedule(static)
  for (size_t i = 0; i < num_query; i++) {
    // In direct mode, query i has its result at logical position i (loc = i).
    std::vector<uint64_t> payload_slots = extract_payload_slots(i);
    results[i] = slots_to_bytes(payload_slots);
  }
  
  auto result_convert_time = timer.elapsed();

  // 8. Print performance statistics.
  std::cout << "------------------------------------" << std::endl;
  std::cout << "Performance (Direct Mode): " << std::endl;
  std::cout << "Init time: " << init_time << " ms " << std::endl;
  std::cout << "Gen query time: " << query_time << " ms " << std::endl;
  std::cout << "Gen response time: " << response_time << " ms " << std::endl;
  std::cout << "Extract answer time: " << extract_time << " ms " << std::endl;
  std::cout << "Result convert time: " << result_convert_time << " ms " << std::endl;

  online_time = query_time + response_time + extract_time + result_convert_time;
  std::cout << "Direct Batch PIR online time: " << online_time << " ms " << std::endl;
  std::cout << "Query size: " << query.str().size() / 1024.0 << " KBytes" << std::endl;
  std::cout << "Response size: " << response.str().size() / 1024.0 << " KBytes" << std::endl;

  com_bytes = query.str().size() + response.str().size();

  return results;
}
