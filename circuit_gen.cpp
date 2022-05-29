#include <random>
#include "circuit_gen.h"

std::vector<FHEOperation> construct_machine_circuit(std::map<ulong, std::vector<ulong>> mapping, uint K, uint ciphertext_count, std::vector<int> shift_order) {
    ulong modulus_mask = (1 << K) - 1;

    std::vector<std::vector<std::set<ulong>>> rotation_masks = {};
    std::vector<std::vector<std::set<ulong>>> output_masks = {};

    // Initialize empty rotation_masks
    for (uint i = 0; i < K; ++i) {
        std::vector<std::set<ulong>> rotation_masks_row = {};
        for (uint j = 0; j < (i + ciphertext_count); ++j) {
            rotation_masks_row.emplace_back();
        }
        rotation_masks.push_back(rotation_masks_row);
    }
    // Initialize empty output_masks
    for (uint i = 0; i < ciphertext_count; ++i) {
        std::vector<std::set<ulong>> output_masks_row = {};
        for (uint j = 0; j < (K + ciphertext_count); ++j) {
            output_masks_row.emplace_back();
        }
        output_masks.push_back(output_masks_row);
    }

    std::vector<bool> rotation_is_used = {};
    for (uint i = 0; i < K; ++i) {
        rotation_is_used.push_back(false);
    }

    // Compute where to mask
    for (const auto& element : mapping) {
        for (auto to : element.second) {
            ulong d = (to - element.first) & modulus_mask;

            ulong current_position = element.first & modulus_mask;
            ulong ciphertext_index = element.first / (1 << K);

            for (uint i = 0; i < K; ++i) {
                if (((d >> shift_order[i]) & 1) == 1) {
                    rotation_is_used[i] = true;
                    rotation_masks[i][ciphertext_index].insert(current_position);
                    current_position = (current_position + (1 << shift_order[i])) & modulus_mask;
                    ciphertext_index = i + ciphertext_count;
                }
            }
            ulong final_ciphertext = to / (1 << K);
            output_masks[final_ciphertext][ciphertext_index].insert(current_position);
        }
    }

    /// Construct actual circuits
    std::vector<FHEOperation> operations = {};
    std::vector<ulong> rot_result_indices = {};
    for (uint i = 0; i < ciphertext_count; ++i) {
        operations.emplace_back(InputOperation {static_cast<ulong>(i)});
        rot_result_indices.push_back(i);
    }

    // Rotations
    for (uint i = 0; i < K; ++i) {
        if (!rotation_is_used[i]) {
            rot_result_indices.push_back(-1);
            continue;
        }

        std::vector<ulong> sum_indices = {};
        for (uint j = 0; j < (i + ciphertext_count); ++j) {
            auto mask_indices = rotation_masks[i][j];
            if (mask_indices.empty()) {
                continue;
            }
            sum_indices.push_back(operations.size());
            operations.emplace_back(MaskOperation {rot_result_indices[j], mask_indices});
        }

        ulong sum_index;
        if (sum_indices.size() == 1) {
            // If we only need to sum one element, we do not need to sum at all
            sum_index = sum_indices[0];
        } else {
            sum_index = operations.size();
            operations.emplace_back(SumOperation {sum_indices});
        }
        rot_result_indices.push_back(operations.size());
        operations.emplace_back(RotOperation {sum_index, static_cast<uint>(1 << shift_order[i])});
    }

    // Output masking
    std::vector<ulong> output_indices = {};
    for (uint j = 0; j < ciphertext_count; ++j) {
        std::vector<ulong> sum_indices = {};
        for (uint i = 0; i < (K + ciphertext_count); ++i) {
            auto mask_indices = output_masks[j][i];
            if (mask_indices.empty()) {
                continue;
            }
            sum_indices.push_back(operations.size());
            operations.emplace_back(MaskOperation {rot_result_indices[i], mask_indices});
        }

        ulong sum_index;
        if (sum_indices.empty()) {
            sum_index = operations.size();
            operations.emplace_back(ZeroOperation {});
        } else if (sum_indices.size() == 1) {
            // If we only need to sum one element, we do not need to sum at all
            sum_index = sum_indices[0];
        } else {
            sum_index = operations.size();
            operations.emplace_back(SumOperation {sum_indices});
        }
        output_indices.push_back(sum_index);
    }

    for (auto output_index : output_indices) {
        operations.emplace_back(OutputOperation {output_index});
    }

    return operations;
}

// Constructs a circuit performing this mapping where K is the log_2 of the number of ciphertext slots and max_machines
// is the maximum number of parallel machines to generate (by default 0, meaning that any number is fine,
// for permutations this is bounded by K).
std::vector<std::vector<FHEOperation>> construct_circuit(std::vector<std::pair<ulong, ulong>> mapping, uint K, ulong ciphertext_count, uint tries) {
    unsigned seed = std::chrono::system_clock::now().time_since_epoch().count();
    auto rng = std::default_random_engine(seed);

    std::map<string, int> best_coloring;
    uint colors = static_cast<uint>(-1);
    std::map<ulong, std::vector<ulong>> best_reduced_mapping;
    std::vector<int> best_shift_order;

    for (uint t = 0; t < tries; ++t) {
        /// Construct the graph coloring problem
        // Create position vector
        ulong modulus_mask = (1 << K) - 1;
        std::vector<std::vector<ulong>> position_vectors = {};
        size_t mapping_size = mapping.size();
        position_vectors.reserve(K);
        for (uint i = 0; i < K; ++i) {
            std::vector<ulong> inner;
            inner.reserve(mapping_size);
            position_vectors.push_back(inner);
        }

        std::vector<int> shift_order = {};
        shift_order.reserve(K);
        for (uint i = 0; i < K; ++i) {
            shift_order.push_back(i);
        }
        std::shuffle(shift_order.begin(), shift_order.end(), rng);

        std::map<ulong, std::vector<ulong>> reduced_mapping = {};

        for (auto pair: mapping) {
            ulong shift = (pair.second - pair.first) & modulus_mask;

            ulong current_position = pair.first & modulus_mask;

            for (uint i = 0; i < K; ++i) {
                if (((shift >> shift_order[i]) & 1) == 1) {
                    position_vectors[i].push_back(current_position);
                    current_position = (current_position + (1 << shift_order[i])) & modulus_mask;
                } else {
                    position_vectors[i].push_back(-1);
                }
            }

            // Make reduced mapping
            if (reduced_mapping.find(pair.first) == reduced_mapping.end()) {
                std::vector<ulong> vec = {pair.second};
                reduced_mapping.insert(std::pair(pair.first, vec));
            } else {
                reduced_mapping[pair.first].push_back(pair.second);
            }
        }

        // Dictionary of conflicts (for each start index, which other start indices it conflicts with)
        map<string, vector<string>> input_graph = {};

        // Add all vertices to the graph
        for (auto pair: mapping) {
            std::vector<string> empty = {};
            input_graph.insert(std::pair(std::to_string(pair.first), empty));
        }

        // Create graph edges
        for (uint k = 0; k < K; ++k) {
            auto position_vector_inner = position_vectors[k];
            for (ulong i = 0; i < mapping_size; ++i) {
                if (position_vector_inner[i] == static_cast<ulong>(-1)) {
                    continue;
                }

                for (ulong j = (i + 1); j < mapping_size; ++j) {
                    if (position_vector_inner[j] == static_cast<ulong>(-1)) {
                        continue;
                    }

                    if (position_vector_inner[i] == position_vector_inner[j]) {
                        string str_i = std::to_string(mapping[i].first);
                        string str_j = std::to_string(mapping[j].first);

                        input_graph.find(str_i)->second.push_back(str_j);
                        input_graph.find(str_j)->second.push_back(str_i);
                    }
                }
            }
        }

        /// Solve graph coloring
        auto *algorithm = new GraphColoring::Dsatur(input_graph);
        auto coloring = algorithm->color();

        if (static_cast<uint>(algorithm->get_num_colors()) < colors) {
            colors = algorithm->get_num_colors();
            best_coloring = coloring;
            best_reduced_mapping = reduced_mapping;
            best_shift_order = shift_order;
        }
    }

    /// Combine results into final ciphertexts
    std::vector<std::map<ulong, std::vector<ulong>>> separated_mappings;
    for (uint i = 0; i < colors; ++i) {
        std::map<ulong, std::vector<ulong>> new_mapping = {};
        separated_mappings.push_back(new_mapping);
    }
    for (const auto& element : best_coloring) {
        ulong key = std::stoi(element.first);
        separated_mappings[element.second].insert(std::pair(key, best_reduced_mapping[key]));
    }

    std::vector<std::vector<FHEOperation>> circuit_description;
    circuit_description.reserve(colors);
    for (uint i = 0; i < colors; ++i) {
        circuit_description.push_back(construct_machine_circuit(separated_mappings[i], K, ciphertext_count, best_shift_order));
    }

    return circuit_description;
}
