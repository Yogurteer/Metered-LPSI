cmake_minimum_required(VERSION 3.18)
project(PayableLPSI)
# Set the default build type after declaring the project.
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find dependencies.
find_package(OpenSSL REQUIRED)
find_package(OpenMP REQUIRED)
find_package(SEAL 4.1 REQUIRED)
find_package(Kuku 2.1 QUIET REQUIRED)
find_package(Boost REQUIRED COMPONENTS system thread)

# Check whether Kuku was found.
if(NOT Kuku_FOUND)
    message(FATAL_ERROR "Microsoft Kuku: not found")
else()
    message(STATUS "Microsoft Kuku: found")
endif()

# Set the path to the prebuilt libOTe source tree.
set(LIBOTE_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/libOTe" CACHE PATH "Built libOTe source tree")
set(LIBOTE_INSTALL_DIR ${LIBOTE_ROOT}/out/install/linux)
set(LIBOTE_BUILD_DIR ${LIBOTE_ROOT}/out/build/linux)
set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${LIBOTE_INSTALL_DIR})

# Set the PIRANA directory.
set(PIRANA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/PIRANA/src")

# Include directories.
include_directories(
    ${CMAKE_SOURCE_DIR}/include
    ${PIRANA_SRC_DIR}
    ${LIBOTE_ROOT}
    ${LIBOTE_ROOT}/libOTe
    ${LIBOTE_ROOT}/cryptoTools
    ${LIBOTE_ROOT}/cryptoTools/cryptoTools
    ${LIBOTE_ROOT}/thirdparty
    ${LIBOTE_ROOT}/out/coproto
    ${LIBOTE_ROOT}/out/macoro
    ${LIBOTE_BUILD_DIR}
    ${LIBOTE_BUILD_DIR}/libOTe
    ${LIBOTE_BUILD_DIR}/cryptoTools
    ${LIBOTE_BUILD_DIR}/cryptoTools/cryptoTools
    ${LIBOTE_BUILD_DIR}/coproto
    ${LIBOTE_BUILD_DIR}/coproto/coproto
    ${LIBOTE_BUILD_DIR}/macoro
    ${LIBOTE_BUILD_DIR}/macoro/macoro
    ${LIBOTE_INSTALL_DIR}/include
    ${OpenSSL_INCLUDE_DIRS}
)

# Library directories.
link_directories(
    ${LIBOTE_BUILD_DIR}/libOTe
    ${LIBOTE_BUILD_DIR}/cryptoTools/cryptoTools
    ${LIBOTE_BUILD_DIR}/coproto/coproto
    ${LIBOTE_BUILD_DIR}/macoro/macoro
    ${LIBOTE_BUILD_DIR}/thirdparty/KyberOT
    ${LIBOTE_BUILD_DIR}/thirdparty/SimplestOT
    ${LIBOTE_INSTALL_DIR}/lib
)

# PIRANA source files.
set(PIRANA_SOURCES
    ${CMAKE_SOURCE_DIR}/PIRANA/src/client.cc
    ${CMAKE_SOURCE_DIR}/PIRANA/src/server.cc
    ${CMAKE_SOURCE_DIR}/PIRANA/src/pir_parms.cc
    ${CMAKE_SOURCE_DIR}/PIRANA/src/utils.cc
    ${CMAKE_SOURCE_DIR}/PIRANA/src/validation.cc
    ${CMAKE_SOURCE_DIR}/PIRANA/src/batch_pir.cc
)

# LPSI source files.
set(LPSI_SOURCES
    src/sender.cpp
    src/receiver.cpp
    src/main.cpp
    src/config.cpp
    src/cx_oprf.cpp
    src/cx_delivery.cpp
)

# Build the executable.
add_executable(lpsi ${LPSI_SOURCES} ${PIRANA_SOURCES})

# Set linker options.
set_target_properties(lpsi PROPERTIES
    LINK_FLAGS "-no-pie"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

# Link libraries using static library paths.
target_link_libraries(lpsi
    ${LIBOTE_BUILD_DIR}/libOTe/liblibOTe.a
    ${LIBOTE_BUILD_DIR}/cryptoTools/cryptoTools/libcryptoTools.a
    ${LIBOTE_BUILD_DIR}/coproto/coproto/libcoproto.a
    ${LIBOTE_BUILD_DIR}/macoro/macoro/libmacoro.a
    ${LIBOTE_BUILD_DIR}/thirdparty/KyberOT/libKyberOT.a
    ${LIBOTE_BUILD_DIR}/thirdparty/SimplestOT/libSimplestOT.a
    SEAL::seal
    Kuku::kuku
    OpenSSL::SSL
    OpenSSL::Crypto
    OpenMP::OpenMP_CXX
    ${Boost_LIBRARIES}
    ${LIBOTE_INSTALL_DIR}/lib/libsodium.a
    pthread
)

if(OpenMP_CXX_FOUND)
    target_link_libraries(lpsi OpenMP::OpenMP_CXX)
endif()

# Compiler options.
target_compile_options(lpsi PRIVATE
    -Wall
    -Wextra
    -Wno-unused-parameter
    -O3
    -march=native
    -fcoroutines
    -fPIC
)

# Print the build configuration.
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "OpenSSL version: ${OPENSSL_VERSION}")
message(STATUS "SEAL found: ${SEAL_FOUND}")
message(STATUS "Kuku found: ${Kuku_FOUND}")
message(STATUS "libOTe directory: ${LIBOTE_ROOT}")
message(STATUS "libOTe build directory: ${LIBOTE_BUILD_DIR}")

set(CX_H2G ${CMAKE_CURRENT_SOURCE_DIR}/vendor/rust_h2g/target/release/libcx_p256_h2g.a)
find_program(CARGO_EXECUTABLE cargo REQUIRED)
add_custom_command(OUTPUT ${CX_H2G}
    COMMAND ${CARGO_EXECUTABLE} build --release --locked
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/vendor/rust_h2g
    DEPENDS vendor/rust_h2g/Cargo.toml vendor/rust_h2g/Cargo.lock vendor/rust_h2g/src/lib.rs
    VERBATIM)
add_custom_target(rfc9380_build DEPENDS ${CX_H2G})
add_dependencies(lpsi rfc9380_build)
target_link_libraries(lpsi ${CX_H2G} dl m)
