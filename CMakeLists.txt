cmake_minimum_required(VERSION 3.21)
project(permutation_mapping_circuits)

set(CMAKE_CXX_STANDARD 20)

find_package(helib REQUIRED)

add_library(fhe_circuits fhe_circuits.h fhe_circuits.cpp)
add_library(naive naive.h naive.cpp)
add_library(circuit_gen circuit_gen.h circuit_gen.cpp)

add_subdirectory(graph-coloring)

if(${CMAKE_SOURCE_DIR} STREQUAL ${CMAKE_CURRENT_SOURCE_DIR})
    include(FeatureSummary)
    feature_summary(WHAT ALL)
endif()

add_executable(permutation_mapping_circuits main.cpp)

target_link_libraries(permutation_mapping_circuits helib fhe_circuits naive circuit_gen graph-coloring)
