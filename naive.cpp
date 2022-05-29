#include <helib/permutations.h>
#include "naive.h"

using namespace std::chrono;

std::vector<helib::Ctxt> arbitrary_permutation_helib(const helib::Context& context, std::vector<ulong> permutation, uint K, std::vector<helib::Ctxt> ciphertexts, uint depth) {
    auto start = high_resolution_clock::now();
    ulong slots = 1 << K;
    ulong mod_mask = slots - 1;
    ulong ciphertext_count = ciphertexts.size();
    std::vector<std::vector<std::set<uint>>> masks_per_ciphertext;
    masks_per_ciphertext.reserve(ciphertext_count);
    std::vector<std::vector<std::vector<std::pair<uint, uint>>>> permutations;

    // Create an empty mask for each pair of (input, output) ciphertexts
    for (uint i = 0; i < ciphertext_count; ++i) {
        std::vector<std::set<uint>> masks = {};
        std::vector<std::vector<std::pair<uint, uint>>> permutations_per_ciphertext = {};
        masks.reserve(ciphertext_count);
        permutations_per_ciphertext.reserve(ciphertext_count);
        for (uint j = 0; j < ciphertext_count; ++j) {
            masks.emplace_back();
            permutations_per_ciphertext.emplace_back();
        }
        masks_per_ciphertext.push_back(masks);
        permutations.push_back(permutations_per_ciphertext);
    }

    // Go over the permutation and split into multiple masks
    for (uint i = 0; i < ciphertext_count; ++i) {
        for (uint j = 0; j < slots; ++j) {
            auto target = permutation[i * slots + j];
            auto target_ciphertext = target / slots;
            masks_per_ciphertext[i][target_ciphertext].insert(j);
            permutations[i][target_ciphertext].push_back(std::pair(j, target & mod_mask));
        }
    }

    auto stop = high_resolution_clock::now();
    std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

    start = high_resolution_clock::now();
    std::vector<helib::Ctxt> outputs = {};
    outputs.reserve(ciphertext_count);
    std::vector<bool> output_initialized = {};
    output_initialized.reserve(ciphertext_count);
    for (uint i = 0; i < ciphertext_count; ++i) {
        outputs.emplace_back(ciphertexts[i]);
        output_initialized.push_back(false);
    }

    // Go over all masks, ignoring empty masks and executing non-empty ones
    for (uint i = 0; i < ciphertext_count; ++i) {
        for (uint j = 0; j < ciphertext_count; ++j) {
            if (masks_per_ciphertext[i][j].empty()) {
                continue;
            }

            helib::Ptxt<helib::BGV> mask(context);
            for (auto mask_index : masks_per_ciphertext[i][j]) {
                mask[mask_index] = true;
            }
            helib::Ctxt result(ciphertexts[i]);
            result.multByConstant(mask);

            // Create permutation for the specific ciphertext by incorporating all pairs and keeping the rest untouched
            helib::Permut ciphertext_permutation = {};
            std::set<long> remaining;
            for (uint k = 0; k < slots; ++k) {
                ciphertext_permutation.append(-1);
                remaining.insert(k);
            }
            for (auto pair : permutations[i][j]) {
                ciphertext_permutation[pair.second] = pair.first;
                remaining.erase(pair.first);
            }
            for (uint k = 0; k < slots; ++k) {
                if (ciphertext_permutation[k] == -1) {
                    auto element = *remaining.begin();
                    ciphertext_permutation[k] = element;
                    remaining.erase(element);
                }
            }

            // Apply permutation
            helib::PermIndepPrecomp prep(context, depth);
            helib::PermPrecomp precomp(prep, ciphertext_permutation);
            precomp.apply(result);

            // Add to outputs
            if (output_initialized[j]) {
                outputs[j].addCtxt(result);
            } else {
                outputs[j] = result;
                output_initialized[j] = true;
            }
        }
    }

    stop = high_resolution_clock::now();
    std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
    std::cout << outputs[0].bitCapacity() << std::endl;

    return outputs;
}
