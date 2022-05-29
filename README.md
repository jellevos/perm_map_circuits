# Constructing circuits for permutations and mappings across ciphertexts
Thanks for checking out our repository. This is an experimental implementation of a method to map elements accross multiple leveled homomorphic ciphertexts. Currently, only HElib ciphertexts are supported.

## Installing
1. Install HElib following their instructions
2. Run `git submodule update --init --recursive` for the graph coloring library

## Building
Building is simple using `cmake .`.

## Executing
We implemented three different experiments:
1. Benchmarking within-ciphertext permutations
2. Benchmarking across-ciphertext permutations
3. Benchmarking across-ciphertext mappings

To choose one, pass the corresponding number to the program as an argument.
