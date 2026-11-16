#include "server.h"

#include <assert.h>

#include <random>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <omp.h>
#include <sstream>

// Use the global protocol_v2 thread count controlled by -t and resolved at link time.
extern int g_thread_count;

namespace {
inline seal::MemoryPoolHandle thread_local_seal_pool() {
  return seal::MemoryManager::GetPool(seal::mm_prof_opt::mm_force_thread_local);
}

inline int direct_kpir_worker_threads(PirParms &pir_parms) {
  constexpr uint64_t SMALL_QUERY_SERIAL_THRESHOLD = 2048;
  constexpr uint64_t WIDE_COL_SERIAL_THRESHOLD = 4096;
  if (pir_parms.get_num_query() <= SMALL_QUERY_SERIAL_THRESHOLD &&
      pir_parms.get_col_size() >= WIDE_COL_SERIAL_THRESHOLD) {
    return 1;
  }
  return std::max(1, g_thread_count);
}
}

Server::Server(PirParms &pir_parms, bool random_db) : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _evaluator = std::make_unique<seal::Evaluator>(*_context);
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _N = pir_parms.get_seal_parms().poly_modulus_degree();
  _p_modulus = pir_parms.get_seal_parms().plain_modulus().bit_count();
  _pre_rot_steps = pir_parms.get_rotate_step();
  _pre_rotate = pir_parms.get_pre_rotate();
  if (random_db == true) {
    gen_random_db();
    _set_db = true;
    encode_to_ntt_db();  // Encode automatically only when generating a random database.
  } else {
    // For file input, call read_db_from_file() first, then encode_to_ntt_db() explicitly.
    _set_db = false;
  }
};

Server::Server(PirParms &pir_parms, bool is_batch, bool random_db)
    : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _evaluator = std::make_unique<seal::Evaluator>(*_context);
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _N = pir_parms.get_seal_parms().poly_modulus_degree();
  _p_modulus = pir_parms.get_seal_parms().plain_modulus().bit_count();
  _pre_rot_steps = pir_parms.get_rotate_step();
  _pre_rotate = pir_parms.get_pre_rotate();
  if (random_db == true) {
    gen_random_db();
    _set_db = true;
  } else {
    // Todo: read_db from file
  }
  if (_pir_parms.get_is_compress()) {
    batch_encode_to_ntt_db_with_compress();
  } else {
    batch_encode_to_ntt_db_without_compress();
  }
}

Server::Server(PirParms &pir_parms, bool is_batch, bool random_db, std::vector<std::vector<uint64_t>> input_db)
    : _pir_parms(pir_parms) {
  _context = std::make_unique<seal::SEALContext>(pir_parms.get_seal_parms());
  _evaluator = std::make_unique<seal::Evaluator>(*_context);
  _batch_encoder = std::make_unique<seal::BatchEncoder>(*_context);
  _N = pir_parms.get_seal_parms().poly_modulus_degree();
  _p_modulus = pir_parms.get_seal_parms().plain_modulus().bit_count();
  _pre_rot_steps = pir_parms.get_rotate_step();
  _pre_rotate = pir_parms.get_pre_rotate();
  if (random_db == true) {
    gen_random_db();
    _set_db = true;
  } else {
    _raw_db = input_db;
    _set_db = true;
  }
  if (_pir_parms.get_is_compress()) {
    batch_encode_to_ntt_db_with_compress();
  } else {
    batch_encode_to_ntt_db_without_compress();
  }
}

Server::~Server() {}

void Server::gen_random_db() {
  //_raw_db (n, |pl|)
  auto num_payloads = _pir_parms.get_num_payloads();
  auto plain_modulus = _pir_parms.get_seal_parms().plain_modulus().value();
  auto plain_modulus_bit =
      _pir_parms.get_seal_parms().plain_modulus().bit_count();
  auto num_payload_slot = _pir_parms.get_num_payload_slot();
  uint64_t plain_mask = (1 << (plain_modulus_bit - 1)) - 1;

  // database read for encryption
  // each uint32_t save a plaintext < plain_modulus;
  std::cout << "Generate random database for test!" << std::endl;
  std::cout << "Raw database: " << num_payloads << " , (" << num_payload_slot
            << " * " << plain_modulus_bit - 1 << ") -> "
            << num_payload_slot * (plain_modulus_bit - 1) / 8 << " Bytes"
            << std::endl;
  _raw_db.resize(num_payloads);
  uint64_t pi = 0;
  for (auto &payload : _raw_db) {
    payload.resize(num_payload_slot);
    uint64_t test_i = 0;
    for (auto &data : payload) {
      // unsafe random generate, just for generating a test database
      data = rand() & plain_mask;
      // data = test_i & plain_mask;
      // data = pi & plain_mask;
      data = data == 0 ? 8888 : data;
      // assert for test
      assert(data < plain_modulus && data != 0);

      test_i++;
    }
    pi++;
  }
}

bool Server::read_db_from_file(const std::string& filename) {
  std::ifstream infile(filename, std::ios::binary);
  if (!infile.is_open()) {
    std::cerr << "Failed to open database file: " << filename << std::endl;
    return false;
  }
  
  std::cout << "Reading database from file: " << filename << std::endl;
  
  // Read metadata: num_payloads and payload_size_bytes.
  uint64_t file_num_payloads, file_payload_size_bytes;
  infile.read(reinterpret_cast<char*>(&file_num_payloads), sizeof(file_num_payloads));
  infile.read(reinterpret_cast<char*>(&file_payload_size_bytes), sizeof(file_payload_size_bytes));
  
  auto expected_num_payloads = _pir_parms.get_num_payloads();
  
  std::cout << "File metadata: " << file_num_payloads << " payloads, " 
            << file_payload_size_bytes << " bytes per payload" << std::endl;
  std::cout << "Expected: " << expected_num_payloads << " payloads" << std::endl;
  
  if (file_num_payloads != expected_num_payloads) {
    std::cerr << "Database size mismatch!" << std::endl;
    infile.close();
    return false;
  }
  
  // Compute the required number of slots.
  auto plain_modulus_bit = _pir_parms.get_seal_parms().plain_modulus().bit_count();
  auto plain_modulus = _pir_parms.get_seal_parms().plain_modulus().value();
  uint64_t bits_per_slot = plain_modulus_bit - 1;
  uint64_t bits_per_payload = file_payload_size_bytes * 8;
  uint64_t num_payload_slot = (bits_per_payload + bits_per_slot - 1) / bits_per_slot;
  uint64_t plain_mask = (1ULL << bits_per_slot) - 1;
  
  std::cout << "Converting to slots: " << num_payload_slot << " slots per payload" << std::endl;
  std::cout << "Bits per slot: " << bits_per_slot << std::endl;
  
  // Check that the slot count matches the expected value.
  auto expected_num_payload_slot = _pir_parms.get_num_payload_slot();
  if (num_payload_slot != expected_num_payload_slot) {
    std::cerr << "Warning: Calculated slots (" << num_payload_slot 
              << ") != expected slots (" << expected_num_payload_slot << ")" << std::endl;
    std::cerr << "Using calculated value: " << num_payload_slot << std::endl;
  }
  
  // Read the raw bytes.
  std::vector<std::vector<unsigned char>> raw_byte_db(file_num_payloads);
  for (auto& payload : raw_byte_db) {
    payload.resize(file_payload_size_bytes);
    infile.read(reinterpret_cast<char*>(payload.data()), file_payload_size_bytes);
  }
  infile.close();
  
  // Convert to uint64_t slots.
  _raw_db.resize(file_num_payloads);
  for (uint64_t i = 0; i < file_num_payloads; i++) {
    _raw_db[i].resize(num_payload_slot);
    
    // Pack the bytes into slots at bit granularity.
    uint64_t bit_pos = 0;
    for (uint64_t slot_idx = 0; slot_idx < num_payload_slot; slot_idx++) {
      uint64_t value = 0;
      for (uint64_t bit = 0; bit < bits_per_slot && bit_pos < bits_per_payload; bit++, bit_pos++) {
        uint64_t byte_idx = bit_pos / 8;
        uint64_t bit_in_byte = bit_pos % 8;
        uint64_t bit_value = (raw_byte_db[i][byte_idx] >> bit_in_byte) & 1;
        value |= (bit_value << bit);
      }
      // Avoid zero values for the SEAL representation.
      _raw_db[i][slot_idx] = (value == 0) ? 1 : value;
      
      // Check that values are within the valid range.
      if (_raw_db[i][slot_idx] >= plain_modulus) {
        std::cerr << "Error: Converted value " << _raw_db[i][slot_idx] 
                  << " exceeds plain_modulus " << plain_modulus << std::endl;
        return false;
      }
    }
  }
  
  std::cout << "Database loaded and converted successfully: " << file_num_payloads 
            << " payloads, " << num_payload_slot << " slots each" << std::endl;
  _set_db = true;
  return true;
}

// used for PIR single query
void Server::encode_to_ntt_db() {
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encoding database!" << std::endl;

  auto N = _pir_parms.get_seal_parms().poly_modulus_degree();
  auto n = _pir_parms.get_num_payloads();
  auto repeat_time = N < n ? 1 : N / n;

  auto real_rotate = _pre_rotate / repeat_time;

  uint32_t plaintext_size;
  if (repeat_time != 1) {
    plaintext_size =
        std::ceil(_pir_parms.get_col_size() *
                  _pir_parms.get_num_payload_slot() / (double)_pre_rotate) *
        real_rotate;
  } else {
    plaintext_size =
        _pir_parms.get_col_size() * _pir_parms.get_num_payload_slot();
  }

  _encoded_db.resize(plaintext_size);
  std::vector<uint64_t> plain_vector(N, 0);

  auto half_N = N / 2;

  int rotate_step = 0;
  auto rotate_time = 0;
  if (repeat_time == 1) {
    bool rotate_column = 0;
    for (uint64_t pl_slot_index = 0;
         pl_slot_index < _pir_parms.get_num_payload_slot(); pl_slot_index++) {
      for (uint64_t col_index = 0; col_index < _pir_parms.get_col_size();
           col_index++) {
        seal::Plaintext encoded_plain;
        for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
             i++, rotate_index++) {
          auto raw_db_index =
              rotate_column ? col_index * N + i + half_N : col_index * N + i;
          plain_vector.at(rotate_index % half_N) =
              _raw_db.at(raw_db_index).at(pl_slot_index);
        }
        for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
             i++, rotate_index++) {
          auto raw_db_index =
              rotate_column ? col_index * N + i : col_index * N + i + half_N;
          plain_vector.at(rotate_index % half_N + half_N) =
              _raw_db.at(raw_db_index).at(pl_slot_index);
        }

        _batch_encoder->encode(plain_vector, encoded_plain);
        _evaluator->transform_to_ntt_inplace(encoded_plain,
                                             _context->first_parms_id());
        _encoded_db.at(pl_slot_index * _pir_parms.get_col_size() + col_index) =
            encoded_plain;
      }

      rotate_step += _pir_parms.get_rotate_step();
      rotate_step = rotate_step % half_N;
      rotate_time++;
      if (rotate_time % (_pir_parms.get_pre_rotate() / 2) == 0) {
        rotate_column = !rotate_column;
      }
    }
  } else {
    for (uint64_t pl_slot_index = 0; pl_slot_index < plaintext_size;
         pl_slot_index++) {
      seal::Plaintext encoded_plain;
      for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
           i++, rotate_index++) {
        auto raw_db_index = i % n;
        auto slot = rotate_time + real_rotate * (i / n);

        if (slot >= _pir_parms.get_num_payload_slot()) {
          plain_vector.at(rotate_index % half_N + half_N) = 0;
          continue;
        }
        plain_vector.at(rotate_index % half_N) =
            _raw_db.at(raw_db_index).at(slot);
      }
      for (uint32_t i = 0, rotate_index = rotate_step; i < half_N;
           i++, rotate_index++) {
        auto raw_db_index = i % n;
        auto slot = rotate_time + real_rotate * (i / n) + _pre_rotate / 2;
        if (slot >= _pir_parms.get_num_payload_slot()) {
          plain_vector.at(rotate_index % half_N + half_N) = 0;
          continue;
        }
        plain_vector.at(rotate_index % half_N + half_N) =
            _raw_db.at(raw_db_index).at(slot);
      }
      _batch_encoder->encode(plain_vector, encoded_plain);
      _evaluator->transform_to_ntt_inplace(encoded_plain,
                                           _context->first_parms_id());
      _encoded_db.at(pl_slot_index) = encoded_plain;
      rotate_step += _pir_parms.get_rotate_step();
      rotate_step = rotate_step % half_N;
      rotate_time++;
      if (rotate_time % real_rotate == 0) {
        rotate_step = 0;
        rotate_time += _pre_rotate - real_rotate;
      }
    }
  }
  std::cout << "Encoding END!" << std::endl;
};

// used for batch encode
void Server::batch_encode_to_ntt_db_without_compress() {
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encode database now!" << std::endl;
  auto num_payload_slot = _pir_parms.get_num_payload_slot();
  auto col_size_val     = _pir_parms.get_col_size();
  auto bundle_size      = _pir_parms.get_bundle_size();
  auto db_pt_size       = col_size_val * bundle_size * num_payload_slot;
  auto bucket           = _pir_parms.get_bucket();
  auto first_parms_id   = _context->first_parms_id();
  int worker_threads    = direct_kpir_worker_threads(_pir_parms);

  _encoded_db.resize(db_pt_size);

  #pragma omp parallel num_threads(worker_threads)
  {
    auto pool = thread_local_seal_pool();
    seal::BatchEncoder batch_encoder(*_context);
    seal::Evaluator evaluator(*_context);

    #pragma omp for collapse(2) schedule(static)
    for (uint64_t pl_slot_index = 0; pl_slot_index < num_payload_slot; pl_slot_index++) {
      for (uint64_t col_index = 0; col_index < col_size_val; col_index++) {
        for (uint32_t bundle_index = 0; bundle_index < bundle_size; bundle_index++) {
          std::vector<uint64_t> local_plain(_N, 0);
          seal::Plaintext encoded_plain(pool);
          for (uint64_t i = 0; i < _N; i++) {
            if (col_index < bucket[bundle_index * _N + i].size()) {
              auto index = bucket[bundle_index * _N + i][col_index];
              local_plain.at(i) = _raw_db.at(index).at(pl_slot_index);
            } else {
              local_plain.at(i) = 1;
            }
          }
          batch_encoder.encode(local_plain, encoded_plain);
          evaluator.transform_to_ntt_inplace(encoded_plain, first_parms_id, pool);
          _encoded_db.at(pl_slot_index * col_size_val * bundle_size +
                         col_index * bundle_size + bundle_index) = encoded_plain;
        }
      }
    }
  }
}

void Server::batch_encode_to_ntt_db_with_compress() {
  assert(_set_db && "Database has not been loaded correctly!");
  std::cout << "Encode database now! (Compress Mode)" << std::endl;

  auto compress_num_slot = _pir_parms.get_batch_pir_num_compress_slot();
  auto table_size = _pir_parms.get_table_size();
  uint32_t num_slot = _pir_parms.get_num_slot();
  auto bundle_size = _pir_parms.get_bundle_size();  // always 1 in compress mode
  uint64_t col_size_val = _pir_parms.get_col_size();
  auto num_payload_slot = _pir_parms.get_num_payload_slot();
  auto first_parms_id = _context->first_parms_id();
  int worker_threads = direct_kpir_worker_threads(_pir_parms);

  // DB layout: [ct_chunk][col][bundle]
  // Each ciphertext ct_chunk encodes payload slots [ct_chunk*num_slot .. (ct_chunk+1)*num_slot)
  // Row i of the table occupies BFV slots [i*num_slot .. (i+1)*num_slot)
  // So payload slot (ct_chunk*num_slot + sl) for row i is at BFV slot i*num_slot + sl
  auto db_pt_size = compress_num_slot * col_size_val * bundle_size;
  auto bucket = _pir_parms.get_bucket();
  _encoded_db.resize(db_pt_size);

  #pragma omp parallel num_threads(worker_threads)
  {
    auto pool = thread_local_seal_pool();
    seal::BatchEncoder batch_encoder(*_context);
    seal::Evaluator evaluator(*_context);

    #pragma omp for collapse(2) schedule(static)
    for (uint64_t ct_chunk = 0; ct_chunk < compress_num_slot; ct_chunk++) {
      for (uint64_t col_index = 0; col_index < col_size_val; col_index++) {

        std::vector<std::vector<uint64_t>> local_plain(bundle_size, std::vector<uint64_t>(_N, 0));

        for (uint32_t i = 0; i < table_size; i++) {
          if (col_index < bucket.at(i).size()) {
            auto item_index = bucket.at(i).at(col_index);

            for (uint32_t sl = 0; sl < num_slot; sl++) {
              uint64_t payload_idx = ct_chunk * num_slot + sl;
              if (payload_idx >= num_payload_slot) break;

              uint64_t raw_pos   = (uint64_t)i * num_slot + sl;
              uint64_t bundle_idx = raw_pos / _N;
              uint64_t slot_idx   = raw_pos % _N;

              if (bundle_idx < bundle_size) {
                local_plain[bundle_idx][slot_idx] = _raw_db.at(item_index).at(payload_idx);
              }
            }
          }
        }

        for (uint32_t b = 0; b < bundle_size; b++) {
          seal::Plaintext encoded_plain(pool);
          batch_encoder.encode(local_plain[b], encoded_plain);
          evaluator.transform_to_ntt_inplace(encoded_plain, first_parms_id, pool);

          uint64_t db_index = (ct_chunk * col_size_val * bundle_size) +
                              (col_index * bundle_size) + b;
          _encoded_db.at(db_index) = encoded_plain;
        }
      }
    }
  }
}

std::vector<seal::Ciphertext> Server::load_query(
    std::stringstream &query_stream, uint32_t query_ct_size) {
  std::vector<seal::Ciphertext> query(query_ct_size);
  for (auto &x : query) {
    x.load(*_context, query_stream);
  }
  return query;
};

void Server::selection_vector_debug(
    std::vector<seal::Ciphertext> &selection_vectors) {
  uint64_t N = _pir_parms.get_seal_parms().poly_modulus_degree();
  uint64_t s = selection_vectors.size();
  for (uint64_t i = 0; i < s; i++) {
    seal::Plaintext encoded_result;
    if (selection_vectors.at(i).is_ntt_form())
      _evaluator->transform_from_ntt_inplace(selection_vectors.at(i));
    _decryptor->decrypt(selection_vectors.at(i), encoded_result);
    std::vector<uint64_t> result(N, 0);
    _batch_encoder->decode(encoded_result, result);
    for (uint64_t slot = 0; slot < N; slot++) {
      if (result.at(slot) != 0) {
        std::cout << "*Debug* No. selection vectors: " << i << std::endl;
        std::cout << "*Debug* result index: " << slot << " response "
                  << result.at(slot) << std::endl;
      }
    }
  }
}

std::vector<seal::Ciphertext> Server::gen_selection_vector(
    std::vector<seal::Ciphertext> &query) {
  std::vector<seal::Ciphertext> selection_vector;
  uint64_t col_size = _pir_parms.get_col_size();
  selection_vector.resize(col_size);
  uint64_t encoding_size = _pir_parms.get_encoding_size();
  uint64_t col_index = 0;
  if (encoding_size == 1) {
    selection_vector[0] = query[0];
  } else {
    for (uint64_t i_1 = 1; i_1 < encoding_size && col_index < col_size; i_1++) {
      for (uint64_t i_2 = 0; i_2 < i_1 && col_index < col_size; i_2++) {
        multiply(*_context, query.at(i_1), query.at(i_2),
                 selection_vector.at(col_index));
        _evaluator->relinearize_inplace(selection_vector.at(col_index),
                                        _relin_keys);
        col_index++;
      }
    }
  }
  return selection_vector;
}

std::vector<seal::Ciphertext> Server::gen_selection_vector_batch(
    std::vector<seal::Ciphertext> &query) {
  std::vector<seal::Ciphertext> selection_vector;
  auto col_size = _pir_parms.get_col_size();
  auto bundle_size = _pir_parms.get_bundle_size();
  selection_vector.resize(col_size * bundle_size);
  auto encoding_size = _pir_parms.get_encoding_size();
  int worker_threads = direct_kpir_worker_threads(_pir_parms);

  // Todo: now only support hamming weight k = 2
  // Try to support more k
  #pragma omp parallel num_threads(worker_threads)
  {
    auto pool = thread_local_seal_pool();
    seal::Evaluator evaluator(*_context);

    #pragma omp for schedule(dynamic)
    for (uint64_t i_1 = 1; i_1 < encoding_size; i_1++) {
      uint64_t pair_base = i_1 * (i_1 - 1) / 2;
      if (pair_base >= col_size) {
        continue;
      }

      for (uint64_t i_2 = 0; i_2 < i_1; i_2++) {
        uint64_t pair_index = pair_base + i_2;
        if (pair_index >= col_size) {
          break;
        }

        for (uint32_t bundle_index = 0; bundle_index < bundle_size;
             bundle_index++) {
          auto &dst = selection_vector.at(pair_index * bundle_size + bundle_index);
          multiply(*_context, query.at(i_1 * bundle_size + bundle_index),
                   query.at(i_2 * bundle_size + bundle_index), dst, pool);
          evaluator.relinearize_inplace(dst, _relin_keys, pool);
          evaluator.transform_to_ntt_inplace(dst);
        }
      }
    }
  }
  // Todo: test selection vector debug
  // selection_vector_debug(selection_vector);
  return selection_vector;
}

// rotate the selection vector and transform them to ntt form
std::vector<seal::Ciphertext> Server::rotate_selection_vector(
    const std::vector<seal::Ciphertext> &selection_vectors) {
  // Todo: make sure have_done computed correctly
  // Add some explanation comments
  uint64_t have_done = std::max(1, int(_N / _pir_parms.get_num_payloads()));

  uint64_t rot_factor = _pre_rotate / have_done;

  // std::cout << "Repead times in one ciphertext: " << have_done << std::endl;
  // std::cout << "One to n: " << _pre_rotate << std::endl;
  std::vector<seal::Ciphertext> rotated_selection_vectors(
      selection_vectors.size() * rot_factor);

  if (_pre_rotate <= 1) {
    // Don't need to rotate the selection vector
    for (size_t i = 0; i < selection_vectors.size(); i++) {
      _evaluator->transform_to_ntt(selection_vectors[i],
                                   rotated_selection_vectors[i]);
    }
    return rotated_selection_vectors;
  }
  if (have_done == 1) {
    for (uint64_t sv_i = 0; sv_i < selection_vectors.size(); sv_i++) {
      rotated_selection_vectors[sv_i * _pre_rotate] = selection_vectors[sv_i];
      _evaluator->rotate_columns(
          selection_vectors[sv_i], _galois_keys,
          rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2]);

      // Continuous rotating same steps can use the same Galois key.
      // [0,0,1,0,0,0,0,0]
      // [0,0,0,0,0,0,1,0]
      for (uint64_t j = 0; j < _pre_rotate / 2 - 1; j++) {
        _evaluator->rotate_rows(
            rotated_selection_vectors[sv_i * _pre_rotate + j], -_pre_rot_steps,
            _galois_keys,
            rotated_selection_vectors[sv_i * _pre_rotate + j + 1]);
      }
      for (uint64_t j = 0; j < _pre_rotate / 2 - 1; j++) {
        _evaluator->rotate_rows(
            rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2 + j],
            -_pre_rot_steps, _galois_keys,
            rotated_selection_vectors[sv_i * _pre_rotate + _pre_rotate / 2 + j +
                                      1]);
      }
    }
  } else {
    // The 'have_done > 1' means poly_degree > n, and floor(poly_degree/n) > 2;
    // The first row and the second row in the BFV ciphertext is same.
    // Don't need to swap rows.
    uint64_t todo = _pre_rotate / have_done;
    assert(selection_vectors.size() == 1);
    rotated_selection_vectors[0] = selection_vectors[0];
    for (uint64_t j = 0; j < todo - 1; j++) {
      _evaluator->rotate_rows(rotated_selection_vectors[j], -_pre_rot_steps,
                              _galois_keys, rotated_selection_vectors[j + 1]);
    }
  }

  // selection_vector_debug(rotated_selection_vectors);
  for (auto &c : rotated_selection_vectors)
    _evaluator->transform_to_ntt_inplace(c);
  return rotated_selection_vectors;
}

std::vector<seal::Ciphertext> Server::mul_database_with_compress(
    const std::vector<seal::Ciphertext> &rotated_selection_vectors) {
  // preprocess the n to be a power of 2
  uint64_t sel_vector_size = _pir_parms.get_col_size();
  uint64_t num_output_ciphers =
      std::ceil((double)_pir_parms.get_num_payload_slot() / _N);

  uint64_t repeat_time = std::max(1, (int)(_N / _pir_parms.get_num_payloads()));

  uint64_t real_rotate = _pre_rotate / repeat_time;
  assert(real_rotate * _pir_parms.get_col_size() ==
         rotated_selection_vectors.size());
  uint64_t total_mul = 0;
  if (repeat_time == 1) {
    total_mul = _pir_parms.get_num_payload_slot();
  } else {
    total_mul =
        std::ceil((double)_pir_parms.get_num_payload_slot() / _pre_rotate) *
        _pre_rotate;
  }

  uint64_t rot = _N / _pre_rotate;

  uint64_t total_rot =
      std::ceil((double)_pir_parms.get_num_payload_slot() / _pre_rotate);

  std::vector<seal::Ciphertext> response(num_output_ciphers);

  // rotate_mul_res_time
  uint64_t mul_count = 0;
  for (uint64_t out_i = 0; out_i < num_output_ciphers; out_i++) {
    for (uint64_t slot_i = 0, slot_len = std::min(rot, total_rot - out_i * rot);
         slot_i < slot_len; slot_i++) {
      seal::Ciphertext mul_result;
      seal::Ciphertext sum_result;

      for (uint64_t mul_i = 0; mul_i < real_rotate && mul_count < total_mul;
           mul_i++, mul_count++) {
        for (uint64_t col_i = 0; col_i < _pir_parms.get_col_size(); col_i++) {
          _evaluator->multiply_plain(
              rotated_selection_vectors.at(col_i * real_rotate + mul_i),
              _encoded_db.at(mul_count * _pir_parms.get_col_size() + col_i),
              mul_result);
          if (col_i == 0 && mul_i == 0) {
            sum_result = mul_result;
          } else {
            _evaluator->add_inplace(sum_result, mul_result);
          }
        }
      }
      _evaluator->transform_from_ntt_inplace(sum_result);
      if (slot_i == 0) {
        response.at(out_i) = sum_result;
      } else {
        _evaluator->add_inplace(response.at(out_i), sum_result);
      }
      _evaluator->rotate_rows_inplace(response.at(out_i), 1, _galois_keys);
    }
    _evaluator->mod_switch_to_inplace(response.at(out_i),
                                      _context->last_parms_id());
    try_clear_irrelevant_bits(_context->last_context_data()->parms(),
                              response.at(out_i));
  }
  return response;
};

std::stringstream Server::inner_product(
    const std::vector<seal::Ciphertext> &selection_vector) {
  std::stringstream result;
  auto col_size = _pir_parms.get_col_size();
  auto bundle_size = _pir_parms.get_bundle_size();
  auto num_ct = _pir_parms.get_batch_pir_num_compress_slot();

  std::vector<seal::Ciphertext> multi_add_res(num_ct * bundle_size);
  std::vector<seal::Ciphertext> result_cipher(num_ct * bundle_size);

  std::vector<seal::Ciphertext> tmp_multi_res(col_size);
  for (uint32_t ct = 0; ct < num_ct; ct++) {
    for (uint32_t bundle = 0; bundle < bundle_size; bundle++) {
      for (uint32_t col = 0; col < col_size; col++) {
        // encode_db (num_plot, col_size, bundle_size)
        uint32_t plain_index =
            ct * bundle_size * col_size + bundle + col * bundle_size;
        uint32_t sv_index = bundle + bundle_size * col;
        _evaluator->multiply_plain(selection_vector.at(sv_index),
                                   _encoded_db.at(plain_index),
                                   tmp_multi_res.at(col));
      }
      _evaluator->add_many(tmp_multi_res,
                           multi_add_res.at(ct * bundle_size + bundle));
      _evaluator->transform_from_ntt_inplace(
          multi_add_res.at(ct * bundle_size + bundle));
      _evaluator->mod_switch_to_inplace(
          multi_add_res.at(ct * bundle_size + bundle),
          _context->last_parms_id());
      try_clear_irrelevant_bits(_context->last_context_data()->parms(),
                                multi_add_res.at(ct * bundle_size + bundle));
    }
  }
  for (auto &i : multi_add_res) {
    i.save(result);
  }
  return result;
}

std::stringstream Server::my_inner_product(
    const std::vector<seal::Ciphertext> &selection_vector) {
    
  std::cout << "Server: Executing Inner Product..." << std::endl;
  
  auto bundle_size = _pir_parms.get_bundle_size();
  auto col_size = _pir_parms.get_col_size();
  auto compress_num_slot = _pir_parms.get_batch_pir_num_compress_slot();
  std::stringstream response;

  // Iterate over payload fragments.
  for (uint64_t pl = 0; pl < compress_num_slot; pl++) {
      
      // Iterate over bundles to support large databases in direct mode.
      for (uint32_t b = 0; b < bundle_size; b++) {
          
          seal::Ciphertext sum;
          bool first = true;

          // Iterate over columns.
          for (uint64_t col = 0; col < col_size; col++) {
              
              // 1. Obtain the corresponding selection vector.
              // Selection Vector Layout: [Col0_B0, Col0_B1...], [Col1_B0...]
              // This matches the output of gen_selection_vector_batch.
              uint64_t sel_idx = col * bundle_size + b;
              
              // 2. Obtain the corresponding database fragment.
              // Encoded DB Layout: [Payload][Col][Bundle]
              // This matches the ordering used in batch_encode...with_compress.
              uint64_t db_idx = (pl * col_size * bundle_size) + (col * bundle_size) + b;

              // 3. Multiply and accumulate: Ciphertext * Plaintext.
              seal::Ciphertext prod;
              
              // gen_selection_vector_batch produces ciphertexts in NTT form.
              // The plaintexts in _encoded_db are also in NTT form.
              // The operands can therefore be passed directly to multiply_plain.
              _evaluator->multiply_plain(selection_vector[sel_idx], _encoded_db[db_idx], prod);

              if (first) {
                  sum = prod;
                  first = false;
              } else {
                  _evaluator->add_inplace(sum, prod);
              }
          }

          // 4. Postprocess: return to coefficient form and reduce the modulus level.
          _evaluator->transform_from_ntt_inplace(sum);
          
          // Switch to the last modulus level expected by client-side decryption.
          while (sum.parms_id() != _context->last_parms_id()) {
               _evaluator->mod_switch_to_next_inplace(sum);
          }

          sum.save(response);
      }
  }
  return response;
}

std::stringstream Server::gen_response(std::stringstream &query_stream) {
  std::stringstream response;
  std::vector<seal::Ciphertext> query =
      load_query(query_stream, _pir_parms.get_encoding_size());

  std::vector<seal::Ciphertext> selection_vector = gen_selection_vector(query);
  std::vector<seal::Ciphertext> rotated_selection_vectors =
      rotate_selection_vector(selection_vector);

  std::vector<seal::Ciphertext> response_cipher =
      mul_database_with_compress(rotated_selection_vectors);

  for (auto &r : response_cipher) {
    r.save(response);
  }
  return response;
};

std::stringstream Server::gen_batch_response(std::stringstream &query_stream) {
  std::vector<seal::Ciphertext> query =
      load_query(query_stream,
                 _pir_parms.get_encoding_size() * _pir_parms.get_bundle_size());

  std::vector<seal::Ciphertext> selection_vector =
      gen_selection_vector_batch(query);
  std::stringstream response;
  response = inner_product(selection_vector);
  return response;
};

std::stringstream Server::gen_direct_batch_response_no_cuckoo(std::stringstream &query_stream) {
  std::cout << "Server: Generating Direct Batch Response (Direct Mode)..." << std::endl;
  double total_start = omp_get_wtime();

  auto bundle_size = _pir_parms.get_bundle_size();
  auto encoding_size = _pir_parms.get_encoding_size(); 
  auto compress_num_slot = _pir_parms.get_batch_pir_num_compress_slot();
  auto col_size = _pir_parms.get_col_size();
  int worker_threads = direct_kpir_worker_threads(_pir_parms);

  // 1. Load all queries: encoding_size * bundle_size entries.
  // Client layout: [m0_b0, m0_b1, m1_b0, m1_b1, ..., m(m-1)_b0, m(m-1)_b1].
  double load_start = omp_get_wtime();
  std::vector<seal::Ciphertext> all_queries = 
      load_query(query_stream, encoding_size * bundle_size);
  double load_time_ms = (omp_get_wtime() - load_start) * 1000.0;

  // 2. Generate selection vectors from the complete query without splitting it.
  // gen_selection_vector_batch expects encoding_size * bundle_size inputs.
  // Output size: col_size * bundle_size.
  double selection_start = omp_get_wtime();
  std::vector<seal::Ciphertext> selection_vector = 
      gen_selection_vector_batch(all_queries);
  double selection_time_ms = (omp_get_wtime() - selection_start) * 1000.0;

  // Preallocate an output slot for each (pl, b), write in parallel, then merge in order.
  uint64_t total_out = compress_num_slot * bundle_size;
  std::vector<std::stringstream> slot_bufs(total_out);

  // 3. Compute inner products in parallel over pl; process b sequentially to preserve bundle order.
  double response_start = omp_get_wtime();
  #pragma omp parallel num_threads(worker_threads)
  {
      auto pool = thread_local_seal_pool();
      seal::Evaluator evaluator(*_context);

      #pragma omp for schedule(dynamic)
      for (uint64_t pl = 0; pl < compress_num_slot; pl++) {
          for (uint32_t b = 0; b < bundle_size; b++) {

              seal::Ciphertext sum(pool);
              bool first = true;

              for (uint64_t col = 0; col < col_size; col++) {
                  uint64_t sel_idx = col * bundle_size + b;
                  uint64_t db_idx  = (pl * col_size * bundle_size) + (col * bundle_size) + b;

                  seal::Ciphertext prod(pool);
                  evaluator.multiply_plain(selection_vector[sel_idx], _encoded_db[db_idx], prod, pool);

                  if (first) {
                      sum = prod;
                      first = false;
                  } else {
                      evaluator.add_inplace(sum, prod);
                  }
              }

              evaluator.transform_from_ntt_inplace(sum);
              while (sum.parms_id() != _context->last_parms_id()) {
                  evaluator.mod_switch_to_next_inplace(sum);
              }

              sum.save(slot_bufs[pl * bundle_size + b]);
          }
      }
  }
  double response_time_ms = (omp_get_wtime() - response_start) * 1000.0;

  // Merge in order to preserve the client's decryption order.
  double merge_start = omp_get_wtime();
  std::stringstream response;
  for (uint64_t i = 0; i < total_out; i++) {
      response << slot_bufs[i].rdbuf();
  }
  double merge_time_ms = (omp_get_wtime() - merge_start) * 1000.0;
  std::cout << "Server: direct response timing breakdown"
            << " [load " << std::fixed << std::setprecision(1) << load_time_ms
            << " ms, selection " << selection_time_ms
            << " ms, inner-product " << response_time_ms
            << " ms, merge " << merge_time_ms
            << " ms, total " << ((omp_get_wtime() - total_start) * 1000.0)
            << " ms]" << std::endl;

  return response;
}
