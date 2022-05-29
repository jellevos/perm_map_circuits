#ifndef PERMUTATION_MAPPING_CIRCUITS_FHE_CIRCUITS_H
#define PERMUTATION_MAPPING_CIRCUITS_FHE_CIRCUITS_H

#include <helib/helib.h>
#include <helib/permutations.h>
#include "circuit_gen.h"

// Accepts a vector of vector of FHEOperations. The inner vector is executed sequentially, while the outer vector can be executed in separate threads.
std::vector<std::vector<helib::Ctxt>> execute_circuits(const helib::Context& context, std::vector<std::vector<FHEOperation>> circuit, std::vector<helib::Ctxt> ciphertexts, const helib::PubKey& public_key, bool is_even, bool verbose = false);

// Same function as execute_circuit, but also aggregates the final result (this is only possible when you know that there is no overlap in the final ciphertexts)
std::vector<helib::Ctxt> execute_circuits_aggregated(const helib::Context& context, std::vector<std::vector<FHEOperation>> circuit, std::vector<helib::Ctxt> ciphertexts, const helib::PubKey& public_key, bool is_even, bool verbose = false);

#endif //PERMUTATION_MAPPING_CIRCUITS_FHE_CIRCUITS_H
