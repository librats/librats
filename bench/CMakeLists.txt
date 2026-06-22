cmake_minimum_required(VERSION 3.14)
project(librats_bench CXX)

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
endif()

set(LIBRATS_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# ── Reference libraries (optional; fetched if the network allows) ────────────
include(FetchContent)
set(FETCHCONTENT_QUIET OFF)

# nlohmann/json — single header.
FetchContent_Declare(nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    URL_HASH SHA256=9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6
    DOWNLOAD_NO_EXTRACT TRUE
)
# RapidJSON — header-only tree; populate without building its tests.
FetchContent_Declare(rapidjson
    GIT_REPOSITORY https://github.com/Tencent/rapidjson.git
    GIT_TAG 24b5e7a8b27f42fa16b96fc70aade9106cf7102f  # master @ 2023, stable headers
    GIT_SHALLOW TRUE
)

set(BENCH_DEFS "")
set(BENCH_INCLUDES "")

# nlohmann
FetchContent_GetProperties(nlohmann_json)
if(NOT nlohmann_json_POPULATED)
    FetchContent_Populate(nlohmann_json)
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

# rapidjson
FetchContent_GetProperties(rapidjson)
if(NOT rapidjson_POPULATED)
    FetchContent_Populate(rapidjson)
endif()
if(EXISTS "${rapidjson_SOURCE_DIR}/include/rapidjson/document.h")
    list(APPEND BENCH_INCLUDES "${rapidjson_SOURCE_DIR}/include")
    list(APPEND BENCH_DEFS BENCH_HAVE_RAPIDJSON=1)
    message(STATUS "bench: RapidJSON available")
else()
    message(WARNING "bench: RapidJSON NOT available — skipping that column")
endif()

# ── The benchmark target ─────────────────────────────────────────────────────
# We compile librats' json.cpp directly (rather than linking the Debug library)
# so the code under test is optimized identically to the reference libraries.
add_executable(bench_json
    bench_json.cpp
    ${LIBRATS_ROOT}/src/util/json.cpp
    stable_json.cpp                       # previous-commit baseline (namespace librats_stable)
)
target_include_directories(bench_json PRIVATE
    ${LIBRATS_ROOT}/src
    ${CMAKE_CURRENT_SOURCE_DIR}           # so stable_json.cpp finds "stable_json.h"
    ${BENCH_INCLUDES}
)
target_compile_definitions(bench_json PRIVATE ${BENCH_DEFS})

# Memory-footprint benchmark — a separate binary so its allocation instrumentation
# never perturbs bench_json's timing numbers.
add_executable(bench_mem
    bench_mem.cpp
    ${LIBRATS_ROOT}/src/util/json.cpp
    stable_json.cpp                       # previous-commit baseline (namespace librats_stable)
)
target_include_directories(bench_mem PRIVATE
    ${LIBRATS_ROOT}/src
    ${CMAKE_CURRENT_SOURCE_DIR}           # so stable_json.cpp finds "stable_json.h"
    ${BENCH_INCLUDES}
)
target_compile_definitions(bench_mem PRIVATE ${BENCH_DEFS})

# The global operator new/delete override must be the only one in the program,
# so statically link the C++ runtime — otherwise a shared libstdc++ has its own
# operator new and blocks allocated here would be freed across a DLL boundary
# with the wrong size header.
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_link_options(bench_mem PRIVATE -static)
endif()

set_target_properties(bench_json bench_mem PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
)
