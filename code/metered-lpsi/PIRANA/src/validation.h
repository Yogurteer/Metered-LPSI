#ifndef PIRANA_VALIDATION_H
#define PIRANA_VALIDATION_H
#include <assert.h>

#include <getopt.h>
#include <unordered_set>
#include <map>

#include "client.h"
#include "pir_parms.h"
#include "server.h"

void test_batch_pir_correctness(Server &server, std::vector<std::vector<uint64_t>> &answer, std::vector<uint32_t> &query, PirParms &pir_parms);

void test_direct_batch_pir_correctness(Server &server,
                                       std::vector<std::vector<uint64_t>> &answer,
                                       const std::vector<uint32_t> &query_indices,
                                       PirParms &pir_parms);                                

#endif
