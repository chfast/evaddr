cmake_minimum_required(VERSION 3.22)

include(FetchContent)

FetchContent_Declare(
    libsecp256k1
    GIT_REPOSITORY https://github.com/bitcoin-core/secp256k1
    GIT_TAG        v0.3.0
    GIT_SHALLOW    TRUE
)

FetchContent_Declare(
    ethash
    GIT_REPOSITORY https://github.com/chfast/ethash
    GIT_TAG        v1.0.0
    GIT_SHALLOW    TRUE
)

FetchContent_MakeAvailable(libsecp256k1 ethash)

project(evaddr)

set(CMAKE_CXX_STANDARD 20)

add_executable(evaddr main.cpp)
target_link_libraries(evaddr PRIVATE secp256k1_static ethash::keccak)
target_include_directories(evaddr PRIVATE ${libsecp256k1_SOURCE_DIR}/include)
