#ifndef PERMUTATION_MAPPING_CIRCUITS_CIRCUIT_GEN_H
#define PERMUTATION_MAPPING_CIRCUITS_CIRCUIT_GEN_H

#include "map"
#include "set"
#include "graph-coloring/Header/dsatur.hpp"
#include "algorithm"
#include "iostream"

#include <chrono>
using namespace std::chrono;

#include "variant"

struct InputOperation {
    ulong index;
};

struct SumOperation {
    std::vector<ulong> indices;
};

struct MaskOperation {
    ulong index;
    std::set<ulong> mask_indices;
};

struct RotOperation {
    ulong index;
    uint amount;
};

struct ZeroOperation {

};

struct OutputOperation {
    ulong index;
};

typedef std::variant<InputOperation, SumOperation, MaskOperation, RotOperation, ZeroOperation, OutputOperation> FHEOperation;

std::vector<FHEOperation> construct_machine_circuit(std::map<ulong, std::vector<ulong>> mapping, uint K, uint ciphertext_count, std::vector<int> shift_order);

std::vector<std::vector<FHEOperation>> construct_circuit(std::vector<std::pair<ulong, ulong>> mapping, uint K, ulong ciphertext_count, uint tries = 1);

#endif //PERMUTATION_MAPPING_CIRCUITS_CIRCUIT_GEN_H
