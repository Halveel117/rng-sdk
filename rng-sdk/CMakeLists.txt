# RNG-SDK prototype — header-only C++17 library + tools.
#
# Configure/build (any platform):
#   cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
#   cmake --build build --config Release
#   ctest --test-dir build --output-on-failure   (or run build/rng_tests)
#
# Options:
#   -DRNGSDK_USE_OPENSSL=ON   route SHA-256/HMAC through OpenSSL (production
#                             backend; needs OpenSSL dev libs, e.g. via vcpkg)
cmake_minimum_required(VERSION 3.16)
project(rngsdk VERSION 0.1.0 LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

option(RNGSDK_USE_OPENSSL "Use OpenSSL for SHA-256/HMAC instead of the bundled reference implementation" OFF)

# The library itself: header-only (INTERFACE) — consumers just add the
# include dir; nothing to link. This is deliberate for licensability: one
# folder of MIT-licensed headers, no binary artifacts, no dependencies.
add_library(rngsdk INTERFACE)
target_include_directories(rngsdk INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_features(rngsdk INTERFACE cxx_std_17)

# OS entropy (crypto/os_entropy.hpp): Windows needs bcrypt (CNG). MSVC also
# auto-links it via #pragma comment; this covers MinGW/clang consumers. The
# Linux/macOS backends (getrandom/getentropy) are libc calls — nothing to link.
if(WIN32)
  target_link_libraries(rngsdk INTERFACE bcrypt)
endif()

if(RNGSDK_USE_OPENSSL)
  find_package(OpenSSL REQUIRED)
  target_link_libraries(rngsdk INTERFACE OpenSSL::Crypto)
  target_compile_definitions(rngsdk INTERFACE RNGSDK_USE_OPENSSL)
endif()

# Tests, tools and examples build only when this is the top-level project, so
# a consumer using add_subdirectory/FetchContent gets the library targets and
# nothing else (no Threads requirement, no extra executables).
if(CMAKE_SOURCE_DIR STREQUAL PROJECT_SOURCE_DIR)
  set(RNGSDK_TOP_LEVEL ON)
else()
  set(RNGSDK_TOP_LEVEL OFF)
endif()
option(RNGSDK_BUILD_TOOLS "Build tests, tools and examples" ${RNGSDK_TOP_LEVEL})

if(RNGSDK_BUILD_TOOLS)
# Warnings for our own targets (not imposed on SDK consumers).
if(MSVC)
  add_compile_options(/W4 $<$<COMPILE_LANGUAGE:CXX>:/permissive->)
else()
  add_compile_options(-Wall -Wextra -Wpedantic)
endif()

add_executable(rng_tests tests/test_main.cpp)
target_link_libraries(rng_tests PRIVATE rngsdk rngsdk_c_static)
# tools/ is on the test include path so rng_stream's byte sources are covered
# by the same suite as the SDK — a defect there would silently invalidate
# every external statistical-battery result.
target_include_directories(rng_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests
                                             ${CMAKE_CURRENT_SOURCE_DIR}/tools)
# The suite checks that web/verifier.html embeds the same test vectors as
# docs/pf_test_vectors.json. That needs the source tree's location at runtime;
# CMake always writes forward slashes here, so the literal is portable.
target_compile_definitions(rng_tests PRIVATE
                           RNGSDK_SOURCE_DIR="${CMAKE_CURRENT_SOURCE_DIR}")

add_executable(rng_verifier tools/verifier_cli.cpp)
target_link_libraries(rng_verifier PRIVATE rngsdk)

add_executable(rng_pi tools/pi_monte_carlo.cpp)
target_link_libraries(rng_pi PRIVATE rngsdk)

# rng_ode: spec additional task #2 — y'' + y = 0 by von Neumann–Ulam Monte
# Carlo over the Volterra form, plus the engine comparison on it.
add_executable(rng_ode tools/ode_monte_carlo.cpp)
target_link_libraries(rng_ode PRIVATE rngsdk)

add_executable(rng_bench tools/benchmark.cpp)
target_link_libraries(rng_bench PRIVATE rngsdk)

# rng_thread_bench: spec section 6 "scalability (multithreading)" —
# aggregate throughput vs thread count, one engine per thread, no shared
# mutable state. OPEN_RESEARCH #9.
find_package(Threads REQUIRED)
add_executable(rng_thread_bench tools/thread_bench.cpp)
target_link_libraries(rng_thread_bench PRIVATE rngsdk Threads::Threads)

# rng_memory: spec section 6 "memory consumption" — per-type footprint,
# printed by the compiler that built it rather than worked out by hand.
# OPEN_RESEARCH #7b.
add_executable(rng_memory tools/memory_report.cpp)
target_link_libraries(rng_memory PRIVATE rngsdk)

# rng_stream: raw bytes on stdout for the external statistical batteries
# (NIST SP 800-22, Dieharder, TestU01, PractRand) — docs/statistical_testing_runbook.md
add_executable(rng_stream tools/stream.cpp)
target_link_libraries(rng_stream PRIVATE rngsdk)

add_executable(rng_quickstart examples/quickstart.cpp)
target_link_libraries(rng_quickstart PRIVATE rngsdk)

# rng_integration_demo: the code docs/INTEGRATION_GUIDE.md quotes. A build
# target so the guide's quickstart cannot rot into something that no longer
# compiles.
add_executable(rng_integration_demo examples/integration_demo.cpp)
target_link_libraries(rng_integration_demo PRIVATE rngsdk)
endif()

# ---- C ABI wrapper -------------------------------------------------------
# docs/design/2026-09-02-c-abi-wrapper-design.md
#
# Two targets from one source: the shared library is what a licensee drops in,
# the static one is what rng_tests links (no DLL to place next to the test
# exe). RNGSDK_C_STATIC is PUBLIC on the static target so consumers get an
# empty RNGSDK_C_API instead of __declspec(dllimport).
add_library(rngsdk_c SHARED c_api/src/rngsdk_c.cpp)
target_link_libraries(rngsdk_c PRIVATE rngsdk)
target_include_directories(rngsdk_c PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/c_api/include)
target_compile_definitions(rngsdk_c PRIVATE RNGSDK_C_BUILDING)
set_target_properties(rngsdk_c PROPERTIES
                      CXX_VISIBILITY_PRESET hidden
                      VISIBILITY_INLINES_HIDDEN ON)

add_library(rngsdk_c_static STATIC c_api/src/rngsdk_c.cpp)
target_link_libraries(rngsdk_c_static PRIVATE rngsdk)
target_include_directories(rngsdk_c_static PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/c_api/include)
target_compile_definitions(rngsdk_c_static PUBLIC RNGSDK_C_STATIC)
set_target_properties(rngsdk_c_static PROPERTIES
                      CXX_VISIBILITY_PRESET hidden
                      VISIBILITY_INLINES_HIDDEN ON)

if(RNGSDK_BUILD_TOOLS)
# Compiled by the C compiler, linked against the SHARED library: proves the
# header parses as C and that the exports are visible from outside.
#
# Standard pin: C_STANDARD 99 / C_STANDARD_REQUIRED ON is real on GCC and
# Clang (emits -std=gnu99/-std=c99 and errors if unsatisfiable) — that is
# where a licensee's strict-C99 build actually happens. MSVC has no
# /std:c99, so those properties are silently inert there; instead we pin
# MSVC to /std:c11, a strict C99 superset, so this target compiles under a
# *stated* standard rather than MSVC's unstated default. Residual gap: a
# construct that is invalid C99 but valid C11 passes this target on MSVC
# and is only caught by the GCC/Clang C99 build.
add_executable(rng_c_parse_test c_api/tests/c_parse_test.c)
target_link_libraries(rng_c_parse_test PRIVATE rngsdk_c)
set_target_properties(rng_c_parse_test PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON)
target_compile_options(rng_c_parse_test PRIVATE $<$<C_COMPILER_ID:MSVC>:/std:c11>)
add_test(NAME c_abi_parse COMMAND rng_c_parse_test)

enable_testing()
add_test(NAME unit COMMAND rng_tests)
endif()
