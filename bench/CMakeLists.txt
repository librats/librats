cmake_minimum_required(VERSION 3.14)
project(librats_bench C CXX)  # C: the ported Noise primitives (bench_crypto) are .c

# ─────────────────────────────────────────────────────────────────────────────
#  Layout
#
#    framework/   the harness. Project-agnostic, no librats in it: the timing
#                 loop (bench.h) and the operator new/delete counters
#                 (alloc_track). Reusable anywhere.
#    support/     scaffolding a suite needs to exercise librats: mocked sockets,
#                 dataset generators. librats-specific, but not under test.
#    baseline/    frozen copies of the implementation each suite is measured
#                 *against*, in their own namespaces so old and new link into
#                 one binary. Never "fixed" — they must behave like what shipped.
#    suites/      the benchmarks themselves. One file, one executable.
#
#  Everything includes from the bench/ root, so a path says which layer it is:
#  #include "framework/bench.h", "support/net_mock.h", "baseline/stable_json.h".
# ─────────────────────────────────────────────────────────────────────────────

# Benchmarks must be optimized regardless of how the parent tree is configured.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-O3 -DNDEBUG -fno-omit-frame-pointer)
elseif(MSVC)
    add_compile_options(/O2 /DNDEBUG)
    # With the Visual Studio (multi-config) generator CMAKE_BUILD_TYPE is ignored
    # and the default Debug config injects /RTC1, which is incompatible with /O2
    # (compiler error D8016). Strip the runtime-check flags from every config so
    # the bench is always optimized, regardless of how it's built.
    foreach(_cfg "" _DEBUG _RELWITHDEBINFO _MINSIZEREL _RELEASE)
        string(REGEX REPLACE "/RTC[1csu]+" "" CMAKE_CXX_FLAGS${_cfg} "${CMAKE_CXX_FLAGS${_cfg}}")
    endforeach()
endif()

set(LIBRATS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# ── add_bench(<name> SOURCES ... [DEFS ...] [INCLUDES ...] [WIN_LIBS ...]
#                                 [STATIC_RUNTIME]) ─────────────────────────────
#
# STATIC_RUNTIME is for suites that override the global operator new/delete: the
# override must be the only one in the program, so the C++ runtime is linked in
# rather than shared (a shared libstdc++ has its own, and blocks allocated here
# would be freed across a DLL boundary).
function(add_bench name)
    cmake_parse_arguments(A "STATIC_RUNTIME" "" "SOURCES;DEFS;INCLUDES;WIN_LIBS" ${ARGN})

    add_executable(${name} ${A_SOURCES})
    target_include_directories(${name} PRIVATE
        ${LIBRATS_ROOT}/src            # the code under test
        ${CMAKE_CURRENT_SOURCE_DIR}    # framework/ support/ baseline/
        ${A_INCLUDES}
    )
    target_compile_definitions(${name} PRIVATE ${A_DEFS})
    if(WIN32 AND A_WIN_LIBS)
        target_link_libraries(${name} PRIVATE ${A_WIN_LIBS})
    endif()
    if(A_STATIC_RUNTIME AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        target_link_options(${name} PRIVATE -static)
    endif()
    set_target_properties(${name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    )
endfunction()

# ── Reference libraries — bench_json / bench_mem only ────────────────────────
#
# FetchContent_Populate hard-errors when the download fails, which would
# otherwise leave an offline machine unable to configure *any* target here,
# including the I/O suites that have no third-party dependencies at all.
option(BENCH_FETCH_REFS "Fetch nlohmann/json + RapidJSON for the JSON suites" ON)

include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

FetchContent_Declare(nlohmann_json                       # single header
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    URL_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
    DOWNLOAD_NO_EXTRACT TRUE
)
FetchContent_Declare(rapidjson                           # header-only tree
    GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
    GIT_TAG 24b5e7a8b27f42fa16b96fc70aade9106cf7102f     # master @ 2023, stable headers
    GIT_SHALLOW TRUE
)

set(BENCH_DEFS "")
set(BENCH_INCLUDES "")

if(BENCH_FETCH_REFS)
    FetchContent_GetProperties(nlohmann_json)
    if(NOT nlohmann_json_POPULATED)
        FetchContent_Populate(nlohmann_json)
    endif()
endif()
if(EXISTS "${nlohmann_json_SOURCE_DIR}/json.hpp")
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann")
    configure_file("${nlohmann_json_SOURCE_DIR}/json.hpp"
                   "${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann/json.hpp" COPYONLY)
    list(APPEND BENCH_INCLUDES "${CMAKE_CURRENT_BINARY_DIR}/include")
    list(APPEND BENCH_DEFS BENCH_HAVE_NLOHMANN=1)
    message(STATUS "bench: nlohmann/json available")
else()
    message(WARNING "bench: nlohmann/json NOT available — skipping that column")
endif()

if(BENCH_FETCH_REFS)
    FetchContent_GetProperties(rapidjson)
    if(NOT rapidjson_POPULATED)
        FetchContent_Populate(rapidjson)
    endif()
endif()
if(EXISTS "${rapidjson_SOURCE_DIR}/include/rapidjson/document.h")
    list(APPEND BENCH_INCLUDES "${rapidjson_SOURCE_DIR}/include")
    list(APPEND BENCH_DEFS BENCH_HAVE_RAPIDJSON=1)
    message(STATUS "bench: RapidJSON available")
else()
    message(WARNING "bench: RapidJSON NOT available — skipping that column")
endif()

# ── The code under test ──────────────────────────────────────────────────────
#
# librats sources are compiled straight into each benchmark rather than linked
# from the main tree, so what is measured is optimized identically to whatever it
# is being compared against — independent of how the parent tree was configured.

set(JSON_UNDER_TEST ${LIBRATS_ROOT}/src/util/json.cpp)
set(IO_UNDER_TEST
    ${LIBRATS_ROOT}/src/core/receive_buffer.cpp
    ${LIBRATS_ROOT}/src/core/chained_send_buffer.cpp
    ${LIBRATS_ROOT}/src/wire/frame.cpp                   # needs htonl -> ws2_32
)

# Crypto primitives librats ported from noise-c (reference2/). Compiled straight
# in so they are optimized identically to the reference they are measured against.
set(CRYPTO_UNDER_TEST
    ${LIBRATS_ROOT}/src/crypto/sha256.c
    ${LIBRATS_ROOT}/src/crypto/sha512.c
    ${LIBRATS_ROOT}/src/crypto/blake2b.c
    ${LIBRATS_ROOT}/src/crypto/blake2s.c
    ${LIBRATS_ROOT}/src/crypto/chacha.c
    ${LIBRATS_ROOT}/src/crypto/poly1305.c
    ${LIBRATS_ROOT}/src/crypto/curve25519.c
    ${LIBRATS_ROOT}/src/crypto/chachapoly.c
)
# The noise-c reference primitives, each symbol-isolated behind nc_* (baseline/).
set(NOISEC_REF
    baseline/noisec_sha256.c
    baseline/noisec_sha512.c
    baseline/noisec_blake2b.c
    baseline/noisec_blake2s.c
    baseline/noisec_chacha.c
    baseline/noisec_poly1305.c
    baseline/noisec_curve25519.c
    baseline/noisec_aead.c
)

# ── The suites ───────────────────────────────────────────────────────────────

# JSON: librats::Json vs nlohmann vs RapidJSON vs the previous librats::Json.
add_bench(bench_json
    SOURCES  suites/bench_json.cpp ${JSON_UNDER_TEST} baseline/stable_json.cpp
    DEFS     ${BENCH_DEFS}
    INCLUDES ${BENCH_INCLUDES}
)

# JSON: one deliberately nasty document, end to end.
add_bench(bench_complex
    SOURCES  suites/bench_complex.cpp ${JSON_UNDER_TEST}
    DEFS     ${BENCH_DEFS}
    INCLUDES ${BENCH_INCLUDES}
)

# JSON: resident heap of a parsed DOM. A separate binary on purpose — its
# allocation instrumentation would otherwise skew bench_json's timings and
# unfairly penalise allocation-heavy DOMs. (It carries its own operator new
# override, predating framework/alloc_track.h; it needs to tag RapidJSON's
# custom allocator too.)
add_bench(bench_mem
    SOURCES  suites/bench_mem.cpp ${JSON_UNDER_TEST} baseline/stable_json.cpp
    DEFS     ${BENCH_DEFS}
    INCLUDES ${BENCH_INCLUDES}
    STATIC_RUNTIME
)

# I/O: the receive and the send path, current vs pre-5d64343. Both count syscalls
# (support/net_mock.h) and allocations (framework/alloc_track.h).
add_bench(bench_rx
    SOURCES  suites/bench_rx.cpp ${IO_UNDER_TEST}
             baseline/legacy_buffers.cpp framework/alloc_track.cpp
    WIN_LIBS ws2_32
    STATIC_RUNTIME
)
add_bench(bench_tx
    SOURCES  suites/bench_tx.cpp ${IO_UNDER_TEST}
             baseline/legacy_buffers.cpp framework/alloc_track.cpp
    WIN_LIBS ws2_32
    STATIC_RUNTIME
)

# DHT: librats' keyspace primitives vs a standalone re-port of libtorrent's.
# Header-only (src/dht/id.h); brings its own timing loop.
add_bench(bench_dht
    SOURCES suites/bench_dht.cpp
)

# Crypto: librats' Noise primitives vs the noise-c reference they were ported from.
add_bench(bench_crypto
    SOURCES suites/bench_crypto.cpp ${CRYPTO_UNDER_TEST} ${NOISEC_REF}
)
