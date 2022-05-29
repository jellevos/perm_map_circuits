#ifndef PERMUTATION_MAPPING_CIRCUITS_NAIVE_H
#define PERMUTATION_MAPPING_CIRCUITS_NAIVE_H

#include "vector"
#include "map"
#include "set"
#include "helib/helib.h"

std::vector<helib::Ctxt> arbitrary_permutation_helib(const helib::Context& context, std::vector<ulong> permutation, uint K, std::vector<helib::Ctxt> ciphertexts, uint depth);

#endif //PERMUTATION_MAPPING_CIRCUITS_NAIVE_H
