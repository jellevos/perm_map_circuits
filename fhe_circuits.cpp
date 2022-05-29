#include "fhe_circuits.h"

#include <utility>
#include <future>

std::vector<helib::Ctxt> execute_circuit(const helib::Context& context, std::vector<FHEOperation> ops, std::vector<helib::Ctxt> ciphertexts, const helib::PubKey& public_key, bool even_k, bool verbose = false) {
    std::vector<helib::Ctxt> intermediate_ciphertexts = {};
    std::vector<ulong> result_indices = {};
    for (auto op : ops) {
        if (verbose) {
            std::cout << "[" << intermediate_ciphertexts.size() << "] ";
        }

        if (std::holds_alternative<InputOperation>(op)) {
            // When it is an InputOperation
            if (verbose) {
                std::cout << "in: " << std::get<InputOperation>(op).index << std::endl;
            }

            intermediate_ciphertexts.push_back(ciphertexts[std::get<InputOperation>(op).index]);
        } else if (std::holds_alternative<SumOperation>(op)) {
            // When it is a SumOperation
            if (verbose) {
                std::cout << "sum: (";
            }
            if (verbose) {
                std::cout << std::get<SumOperation>(op).indices[0] << " ";
            }
            helib::Ctxt result(intermediate_ciphertexts[std::get<SumOperation>(op).indices[0]]);
            for (uint i = 1; i < std::get<SumOperation>(op).indices.size(); ++i) {
                if (verbose) {
                    std::cout << std::get<SumOperation>(op).indices[i] << " ";
                }
                result.addCtxt(intermediate_ciphertexts[std::get<SumOperation>(op).indices[i]]);
            }
            if (verbose) {
                std::cout << ")" << std::endl;
            }
            intermediate_ciphertexts.push_back(result);
        } else if (std::holds_alternative<MaskOperation>(op)) {
            // When it is a MaskOperation
            if (verbose) {
                std::cout << "mask: " << std::get<MaskOperation>(op).index << " (";
            }
            helib::Ptxt<helib::BGV> mask(context);
            for (auto mask_index : std::get<MaskOperation>(op).mask_indices) {
                if (verbose) {
                    std::cout << mask_index << " ";
                }
                mask[mask_index] = true;
            }
            if (verbose) {
                std::cout << ")" << std::endl;
            }
            helib::Ctxt result(intermediate_ciphertexts[std::get<MaskOperation>(op).index]);
            result.multByConstant(mask);
            intermediate_ciphertexts.push_back(result);
        } else if (std::holds_alternative<RotOperation>(op)) {
            // When it is a RotOperation
            if (verbose) {
                std::cout << "rot<" << std::get<RotOperation>(op).amount << ">: " << std::get<RotOperation>(op).index << std::endl;
            }
            helib::Ctxt result(intermediate_ciphertexts[std::get<RotOperation>(op).index]);
            uint amount = std::get<RotOperation>(op).amount;
            if (even_k) {
                result.smartAutomorph(NTL::PowerMod(3, amount, context.getM()));
            } else {
                if (amount == 1) {
                    rotate(result, 1);
                } else {
                    result.smartAutomorph(NTL::PowerMod(3, amount / 2, context.getM()));
                }
            }

            intermediate_ciphertexts.push_back(result);
        } else if (std::holds_alternative<ZeroOperation>(op)) {
            if (verbose) {
                std::cout << "zero" << std::endl;
            }
            helib::Ptxt<helib::BGV> zero_ptxt(context);
            helib::Ctxt zero_ctxt(public_key);
            public_key.Encrypt(zero_ctxt, zero_ptxt);
            intermediate_ciphertexts.push_back(zero_ctxt);
        } else if (std::holds_alternative<OutputOperation>(op)) {
            if (verbose) {
                std::cout << "out: " << std::get<OutputOperation>(op).index << std::endl;
            }
            auto index = intermediate_ciphertexts.size();
            intermediate_ciphertexts.push_back(intermediate_ciphertexts[std::get<OutputOperation>(op).index]);
            result_indices.push_back(index);
        }
    }

    std::vector<helib::Ctxt> results = {};
    results.reserve(result_indices.size());
    for (auto index : result_indices) {
        results.push_back(intermediate_ciphertexts[index]);
    }

    return results;
}

std::vector<std::vector<helib::Ctxt>> execute_circuits(const helib::Context& context, std::vector<std::vector<FHEOperation>> circuit, std::vector<helib::Ctxt> ciphertexts, const helib::PubKey& public_key, bool is_even, bool verbose) {
    std::vector<std::vector<helib::Ctxt>> final_result = {};

    final_result.reserve(circuit.size());
    for (const auto& ops : circuit) {
        final_result.push_back(execute_circuit(context, ops, ciphertexts, public_key, is_even, verbose));
    }

    return final_result;
}

std::vector<helib::Ctxt> execute_circuits_aggregated(const helib::Context& context, std::vector<std::vector<FHEOperation>> circuit, std::vector<helib::Ctxt> ciphertexts, const helib::PubKey& public_key, bool is_even, bool verbose) {
    auto resulting_ciphertexts = execute_circuits(context, std::move(circuit), std::move(ciphertexts), public_key, is_even, verbose);
    auto final_result = resulting_ciphertexts[0];
    for (uint i = 1; i < resulting_ciphertexts.size(); ++i) {
        for (uint j = 0; j < resulting_ciphertexts[0].size(); ++j) {
            final_result[j].addCtxt(resulting_ciphertexts[i][j]);
        }
    }

    return final_result;
}
