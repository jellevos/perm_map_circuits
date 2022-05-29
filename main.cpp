#include <iostream>

#include "circuit_gen.h"
#include "naive.h"
#include "helib/helib.h"
#include "helib/permutations.h"
#include "fhe_circuits.h"

using namespace std::chrono;

struct ParameterSet {
    const string name;
    const helib::Context& context;
    const helib::SecKey sk;
    const helib::PubKey& pk;
    const long slots;
    const uint tries;
    const uint helib_depth;
    const bool even_k;
};

int within_ciphertext_perm_experiment(const std::vector<ParameterSet>& parameter_sets, uint repetitions, bool verbose = false) {
    std::cout << "Running experiment 1: " << std::endl;

    for (uint i = 0; i < repetitions; ++i) {
        std::cout << "> Repetition " << (i + 1) << "/" << repetitions << std::endl;

        for (const ParameterSet& parameter_set : parameter_sets) {
            std::cout << ">- " << parameter_set.name << " parameter set" << std::endl;
            helib::Ptxt<helib::BGV> ptxt(parameter_set.context);
            // Fill plaintexts up with 0, ..., #slots
            for (uint j = 0; j < ptxt.size(); ++j) {
                ptxt[j] = j;
            }
            helib::Ctxt ctxt(parameter_set.pk);
            parameter_set.pk.Encrypt(ctxt, ptxt);

            // Generate a random permutation
            helib::Permut pi;
            helib::randomPerm(pi, parameter_set.slots);

            /// Measure within-ciphertext permutation times for our work
            vector<std::pair<ulong, ulong>> mapping = {};
            mapping.reserve(parameter_set.slots);
            for (uint j = 0; j < parameter_set.slots; ++j) {
                mapping.emplace_back(pi[j], j);
            }

            // [Our work] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuit" << std::endl;
            }
            auto start = high_resolution_clock::now();
            auto circuit = construct_circuit(mapping, log2(parameter_set.slots), 1);
            auto stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt = execute_circuits_aggregated(parameter_set.context, circuit, {ctxt}, parameter_set.pk, parameter_set.even_k);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit.size() << std::endl;
            std::cout << our_ctxt[0].bitCapacity() << std::endl;

            // [Our work with max machines] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuits (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto circuit_max = construct_circuit(mapping, log2(parameter_set.slots), 1, parameter_set.tries);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work with max machines] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt_max = execute_circuits_aggregated(parameter_set.context, circuit_max, {ctxt}, parameter_set.pk, parameter_set.even_k);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit_max.size() << std::endl;
            std::cout << our_ctxt_max[0].bitCapacity() << std::endl;

            /// Measure within-ciphertext permutation times for HElib
            // [HElib] Set up permutation structure for these contexts
            helib::PermIndepPrecomp helib_prep(parameter_set.context, parameter_set.helib_depth);

            // [HElib] Precompute permutation strategy
            if (verbose) {
                std::cout << "Precompute HElib permutation strategy" << std::endl;
            }
            start = high_resolution_clock::now();
            helib::PermPrecomp helib_precomp(helib_prep, pi);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [HElib] Perform permutation in-place
            if (verbose) {
                std::cout << "Perform HElib permutation" << std::endl;
            }
            start = high_resolution_clock::now();
            helib_precomp.apply(ctxt);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << ctxt.bitCapacity() << std::endl;

            /// Check that our results agree with each other and with HElib
            helib::PtxtArray helib_result(parameter_set.context);
            helib_result.decrypt(ctxt, parameter_set.sk);
            helib::PtxtArray our_result(parameter_set.context);
            our_result.decrypt(our_ctxt[0], parameter_set.sk);
            helib::PtxtArray our_result_max(parameter_set.context);
            our_result_max.decrypt(our_ctxt_max[0], parameter_set.sk);

            if (our_result != our_result_max) {
                std::cout << our_result << std::endl;
                std::cout << our_result_max << std::endl;
                std::cout << "our results are not the same" << std::endl;
                return 1;
            }

            if (helib_result != our_result) {
                std::cout << helib_result << std::endl;
                std::cout << our_result << std::endl;
                std::cout << "our results are not the same as HElib" << std::endl;
                return 1;
            }
        }
    }

    return 0;
}

int across_ciphertext_perm_experiment(const std::vector<ParameterSet>& parameter_sets, uint ciphertext_count, uint repetitions, bool verbose = false) {
    std::cout << "Running experiment 1: " << std::endl;

    for (uint i = 0; i < repetitions; ++i) {
        std::cout << "> Repetition " << (i + 1) << "/" << repetitions << std::endl;

        for (const ParameterSet &parameter_set: parameter_sets) {
            std::cout << ">- " << parameter_set.name << " parameter set" << std::endl;

            std::vector<helib::Ctxt> ciphertexts = {};
            ciphertexts.reserve(ciphertext_count);
            for (uint j = 0; j < ciphertext_count; ++j) {
                helib::Ptxt<helib::BGV> ptxt(parameter_set.context);
                // Fill plaintexts up with 0, ..., #slots
                for (uint k = 0; k < ptxt.size(); ++k) {
                    ptxt[k] = k + j * parameter_set.slots;
                }
                helib::Ctxt ctxt(parameter_set.pk);
                parameter_set.pk.Encrypt(ctxt, ptxt);
                ciphertexts.push_back(ctxt);
            }

            // Generate a random permutation
            helib::Permut pi;
            helib::randomPerm(pi, parameter_set.slots * ciphertext_count);

            /// Measure across-ciphertext permutation times for our work
            vector<std::pair<ulong, ulong>> mapping = {};
            mapping.reserve(parameter_set.slots * ciphertext_count);
            for (uint j = 0; j < parameter_set.slots * ciphertext_count; ++j) {
                mapping.emplace_back(pi[j], j);
            }

            // [Our work] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuit" << std::endl;
            }
            auto start = high_resolution_clock::now();
            auto circuit = construct_circuit(mapping, log2(parameter_set.slots), ciphertext_count);
            auto stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt = execute_circuits_aggregated(parameter_set.context, circuit, ciphertexts, parameter_set.pk, parameter_set.even_k, verbose);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit.size() << std::endl;
            std::cout << our_ctxt[0].bitCapacity() << std::endl;

            // [Our work with max machines] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuits (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto circuit_max = construct_circuit(mapping, log2(parameter_set.slots), ciphertext_count, parameter_set.tries);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work with max machines] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt_max = execute_circuits_aggregated(parameter_set.context, circuit_max, ciphertexts, parameter_set.pk, parameter_set.even_k, verbose);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit_max.size() << std::endl;
            std::cout << our_ctxt_max[0].bitCapacity() << std::endl;

            /// Measure across-ciphertext permutation times for HElib (naive method)
            // [HElib]
            if (verbose) {
                std::cout << "Measure HElib execution times" << std::endl;
            }
            std::vector<ulong> pi_vector;
            for (uint j = 0; j < parameter_set.slots * ciphertext_count; ++j) {
                pi_vector.push_back(0);
            }
            // Invert the permutation (arbitrary_permutation_helib accepts the permutation in the other direction)
            for (uint j = 0; j < parameter_set.slots * ciphertext_count; ++j) {
                pi_vector[pi[j]] = j;
            }
            auto helib_ciphertexts = arbitrary_permutation_helib(parameter_set.context, pi_vector, log2(parameter_set.slots), ciphertexts, parameter_set.helib_depth);

            /// Check that our results agree with each other and with HElib
            for (uint j = 0; j < ciphertext_count; ++j) {
                helib::PtxtArray helib_result(parameter_set.context);
                helib_result.decrypt(helib_ciphertexts[j], parameter_set.sk);
                helib::PtxtArray our_result(parameter_set.context);
                our_result.decrypt(our_ctxt[j], parameter_set.sk);
                helib::PtxtArray our_result_max(parameter_set.context);
                our_result_max.decrypt(our_ctxt_max[j], parameter_set.sk);

                if (our_result != our_result_max) {
                    std::cout << our_result << std::endl;
                    std::cout << our_result_max << std::endl;
                    std::cout << "our results are not the same for the " << j << "th ciphertext" << std::endl;
                    return 1;
                }

                if (helib_result != our_result) {
                    std::cout << helib_result << std::endl;
                    std::cout << our_result << std::endl;
                    std::cout << "our results are not the same as HElib for the " << j << "th ciphertext" << std::endl;
                    return 1;
                }
            }
        }
    }

    return 0;
}

int across_ciphertext_mapping_experiment(const std::vector<ParameterSet>& parameter_sets, uint ciphertext_count, uint replication_degree, uint overlap_degree, uint repetitions, bool verbose = false) {
    std::cout << "Running experiment 1: " << std::endl;

    for (uint i = 0; i < repetitions; ++i) {
        std::cout << "> Repetition " << (i + 1) << "/" << repetitions << std::endl;

        for (const ParameterSet &parameter_set: parameter_sets) {
            std::cout << ">- " << parameter_set.name << " parameter set" << std::endl;

            std::vector<helib::Ctxt> ciphertexts = {};
            ciphertexts.reserve(ciphertext_count);
            for (uint j = 0; j < ciphertext_count; ++j) {
                helib::Ptxt<helib::BGV> ptxt(parameter_set.context);
                // Fill plaintexts up with 0, ..., #slots
                for (uint k = 0; k < ptxt.size(); ++k) {
                    ptxt[k] = k + j * parameter_set.slots;
                }
                helib::Ctxt ctxt(parameter_set.pk);
                parameter_set.pk.Encrypt(ctxt, ptxt);
                ciphertexts.push_back(ctxt);
            }

            /// Generate a random mapping
            vector<std::pair<ulong, ulong>> mapping = {};
            // Create a list of all possible targets (bounded by overlap_degree)
            std::vector<ulong> remaining_targets = {};
            remaining_targets.reserve(overlap_degree * parameter_set.slots * ciphertext_count);
            for (uint j = 0; j < overlap_degree; ++j) {
                for (uint k = 0; k < parameter_set.slots * ciphertext_count; ++k) {
                    remaining_targets.push_back(k);
                }
            }
            // Create a list of all possible sources (bounded by replication_degree)
            std::vector<ulong> remaining_sources = {};
            remaining_sources.reserve(replication_degree * parameter_set.slots * ciphertext_count);
            for (uint j = 0; j < replication_degree; ++j) {
                for (uint k = 0; k < parameter_set.slots * ciphertext_count; ++k) {
                    remaining_sources.push_back(k);
                }
            }
            // Sample until either the set of targets or sources is empty
            srand(time(0));
            while (!remaining_sources.empty() and !remaining_targets.empty()) {
                // Choose a random remaining source and target
                uint source_index = rand() % remaining_sources.size();
                uint target_index = rand() % remaining_targets.size();
                uint source = remaining_sources[source_index];
                uint target = remaining_targets[target_index];

                mapping.emplace_back(source, target);

                remaining_sources.erase(remaining_sources.begin() + source_index);
                remaining_targets.erase(remaining_targets.begin() + target_index);
            }

            /// Measure across-ciphertext permutation times for our work
            // [Our work] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuit" << std::endl;
            }
            auto start = high_resolution_clock::now();
            auto circuit = construct_circuit(mapping, log2(parameter_set.slots), ciphertext_count);
            auto stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt = execute_circuits_aggregated(parameter_set.context, circuit, ciphertexts, parameter_set.pk, parameter_set.even_k, verbose);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit.size() << std::endl;
            std::cout << our_ctxt[0].bitCapacity() << std::endl;

            // [Our work with max machines] Create permutation circuits
            if (verbose) {
                std::cout << "Construct our permutation circuits (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto circuit_max = construct_circuit(mapping, log2(parameter_set.slots), ciphertext_count, parameter_set.tries);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;

            // [Our work with max machines] Measure execution time
            if (verbose) {
                std::cout << "Measure our execution times (10 tries)" << std::endl;
            }
            start = high_resolution_clock::now();
            auto our_ctxt_max = execute_circuits_aggregated(parameter_set.context, circuit_max, ciphertexts, parameter_set.pk, parameter_set.even_k, verbose);
            stop = high_resolution_clock::now();
            std::cout << duration_cast<microseconds>(stop - start).count() << std::endl;
            std::cout << circuit_max.size() << std::endl;
            std::cout << our_ctxt_max[0].bitCapacity() << std::endl;

            /// Check our results
            for (uint j = 0; j < ciphertext_count; ++j) {
                helib::PtxtArray our_result(parameter_set.context);
                our_result.decrypt(our_ctxt[j], parameter_set.sk);
                helib::PtxtArray our_result_max(parameter_set.context);
                our_result_max.decrypt(our_ctxt_max[j], parameter_set.sk);

                if (our_result != our_result_max) {
                    std::cout << our_result << std::endl;
                    std::cout << our_result_max << std::endl;
                    std::cout << "our results are not the same for the " << j << "th ciphertext" << std::endl;
                    return 1;
                }
            }
        }
    }

    return 0;
}

// Takes one input argument, which is an integer denoting which experiment to execute:
// [1] - Run time required to perform within-ciphertext permutations (between HElib, our work, and our work with threads)
// [2] - ...
int main(int argc, char* argv[]) {
    const auto c = 2;
    const bool verbose = false;
    const auto repetitions = 20;
    std::cout << "Verbose: " << verbose << ", repetitions: " << repetitions << std::endl;

    /// Build the contexts
    std::cout << "Setting up ..." << std::endl;
    // Small
    long m = 8192;
    long p = 31;
    long bits = 59;
    helib::Context context_small = helib::ContextBuilder<helib::BGV>()
            .m(m)
            .p(p)
            .r(1)
            .c(c)
            .buildModChain(false)
            .build();
    context_small.buildModChain(bits, c, false, 0, 3, 50);
    if (verbose) {
        context_small.printout();
    }
    helib::SecKey sk_small(context_small);
    sk_small.GenSecKey();
    helib::add1DMatrices(sk_small);
    const helib::PubKey &pk_small = sk_small;
    const auto slots_small = context_small.getNSlots();
    const ParameterSet small_params{"small", context_small, sk_small, pk_small, slots_small, 10, 4, true};

    // Medium
    //m = 16384; p = 257; bits = 120;
    m = 16384;
    p = 127;
    bits = 120;
    helib::Context context_medium = helib::ContextBuilder<helib::BGV>()
            .m(m)
            .p(p)
            .r(1)
            .c(c)
            .buildModChain(false)
            .build();
    context_medium.buildModChain(bits, c, false, 0, 3, 50); // res 3 (164 bits, 172 sec)
    if (verbose) {
        context_medium.printout();
    }
    helib::SecKey sk_medium(context_medium);
    sk_medium.GenSecKey();
    helib::add1DMatrices(sk_medium);
    const helib::PubKey &pk_medium = sk_medium;
    const auto slots_medium = context_medium.getNSlots();
    const ParameterSet medium_params{"medium", context_medium, sk_medium, pk_medium, slots_medium, 10, 7, true};

    // Large
    //m = 32768; p = 6143; bits = 360;
    m = 32768;
    p = 5119;
    bits = 360;
    helib::Context context_large = helib::ContextBuilder<helib::BGV>()
            .m(m)
            .p(p)
            .r(1)
            .c(c)
            .buildModChain(false)
            .build();
    context_large.buildModChain(bits, c, false, 0, 3, 50);
    if (verbose) {
        context_large.printout();
    }
    helib::SecKey sk_large(context_large);
    sk_large.GenSecKey();
    helib::add1DMatrices(sk_large);
    const helib::PubKey &pk_large = sk_large;
    const auto slots_large = context_large.getNSlots();
    const ParameterSet large_params{"large", context_large, sk_large, pk_large, slots_large, 10, 9, true};


    /// If the selected experiment is [1]
    if (argv[1][0] == '1') {
        within_ciphertext_perm_experiment({small_params, medium_params, large_params}, repetitions, verbose);
    } else if (argv[1][0] == '2') {
        for (int i = 1; i <= 10; i += 1) {
            std::cout << "Running for " << i << "/16 ciphertexts" << std::endl;
            across_ciphertext_perm_experiment({small_params, medium_params, large_params}, i, repetitions,
                                              verbose);
        }
    } else if (argv[1][0] == '3') {
        // Try out random mappings in a double for loop for different delta in and delta out
        for (uint i = 1; i < 5; ++i) {
            for (uint j = 1; j < 5; ++j) {
                across_ciphertext_mapping_experiment({small_params, medium_params, large_params}, 8, i, j, repetitions,
                                                     verbose);
            }
        }
    }
}
