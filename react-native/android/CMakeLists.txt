cmake_minimum_required(VERSION 3.22.1)

# The project/library name must match `androidCxxLibName` in nitro.json: the
# generated autolinking .cmake calls target_sources()/target_link_libraries() on
# a target of exactly this name, and Nitrogen's Kotlin loader does
# System.loadLibrary("LibratsRN").
project(LibratsRN)

# C++20, not 17: Nitrogen's generated structs use defaulted operator== (a C++20
# feature). librats itself is C++17 but compiles cleanly as C++20.
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(LibratsRN SHARED
    ../cpp/HybridRatsNode.cpp
    src/main/cpp/cpp-adapter.cpp
)

# --- librats core -----------------------------------------------------------
# Same rule as android/src/main/cpp/CMakeLists.txt: never duplicate
# LIBRARY_SOURCES. Configure the root build for this platform and pull it in.
# Resolve symlinks before walking up. An example app (and any npm/yarn workspace)
# reaches this package through a link — node_modules/react-native-librats -> ../..
# — and CMAKE_CURRENT_SOURCE_DIR keeps the *linked* path, so a plain "../.." lands
# in node_modules instead of the repository root and add_subdirectory() fails.
get_filename_component(LIBRATS_MODULE_ANDROID_DIR "${CMAKE_CURRENT_SOURCE_DIR}" REALPATH)
get_filename_component(LIBRATS_SOURCE_DIR "${LIBRATS_MODULE_ANDROID_DIR}/../.." REALPATH)
set(LIBRATS_BINARY_DIR ${CMAKE_BINARY_DIR}/librats_native)

if(NOT EXISTS "${LIBRATS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "librats root CMakeLists.txt not found at ${LIBRATS_SOURCE_DIR}. This "
        "package expects to live inside the librats repository; a published "
        "package would vendor the sources or a prebuilt library instead.")
endif()

set(RATS_BUILD_CLIENT   OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(RATS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
set(RATS_CROSSCOMPILING ON  CACHE BOOL "" FORCE)
set(RATS_INSTALL        OFF CACHE BOOL "" FORCE)
set(RATS_STATIC_LIBRARY ON  CACHE BOOL "" FORCE)
set(RATS_SHARED_LIBRARY OFF CACHE BOOL "" FORCE)
# The C ABI is not needed here — this binding calls the C++ Node API directly,
# since Nitro is a C++ consumer and has no FFI boundary to flatten across.
set(RATS_BINDINGS       OFF CACHE BOOL "" FORCE)

# The distributed key-value store is off by default in the root build; this
# binding exposes it, so it has to be on here or the storage symbols do not exist
# to link against.
set(RATS_STORAGE        ON  CACHE BOOL "Storage is part of this binding's API" FORCE)
# BitTorrent is on because enableBittorrent() is part of this binding's API. It is
# the one subsystem with a real size cost: it added 17 MB to the arm64 debug library
# (54 -> 71 MB, unstripped). Drop this and the spec's BitTorrent methods together if
# that matters more than the feature does.
set(RATS_SEARCH_FEATURES ON  CACHE BOOL "BitTorrent is part of this binding's API" FORCE)

add_subdirectory(${LIBRATS_SOURCE_DIR} ${LIBRATS_BINARY_DIR})

target_link_libraries(LibratsRN rats)

# --- Nitro ------------------------------------------------------------------
# Adds the generated sources and headers, and links NitroModules, JSI, fbjni and
# react-native (all via prefab).
include(${CMAKE_SOURCE_DIR}/../nitrogen/generated/android/LibratsRN+autolinking.cmake)

target_include_directories(LibratsRN PRIVATE ../cpp)

set_target_properties(LibratsRN PROPERTIES CXX_STANDARD 20)
