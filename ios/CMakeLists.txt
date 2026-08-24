cmake_minimum_required(VERSION 3.19)

# ---------------------------------------------------------------------------
# iOS module for librats.
#
# Mirrors android/src/main/cpp/CMakeLists.txt: it does NOT duplicate the source
# list. The root CMakeLists.txt owns LIBRARY_SOURCES and the generated
# version.h / features.h; this file only configures that build for the platform
# and pulls it in with add_subdirectory.
#
# The toolchain itself comes from the caller (CMAKE_SYSTEM_NAME=iOS plus the
# sysroot/arch), because a device build and a simulator build differ only in
# those flags and both are needed to assemble an XCFramework. Use
# build-xcframework.sh, or configure directly:
#
#   cmake -S ios -B build/ios-device \
#         -DCMAKE_SYSTEM_NAME=iOS \
#         -DCMAKE_OSX_ARCHITECTURES=arm64 \
#         -DCMAKE_OSX_SYSROOT=iphoneos \
#         -DCMAKE_OSX_DEPLOYMENT_TARGET=15.0
# ---------------------------------------------------------------------------

project(librats_ios C CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
    message(FATAL_ERROR
        "This module targets iOS. Pass -DCMAKE_SYSTEM_NAME=iOS (see the header "
        "comment), or build the root CMakeLists.txt directly for macOS.")
endif()

# A try_compile for iOS would link a full executable, which the SDK expects to be
# signed and bundled — so the root's check_cxx_source_compiles() would fail for
# reasons unrelated to what it asks. Restricting try_compile to a static library
# keeps those probes meaningful.
#
# One consequence worth knowing: the root's HAVE_BUILTIN_ATOMIC64 probe becomes a
# compile check rather than a link check, so it always reports "builtin". That is
# the correct answer for every iOS target anyway — all of them are 64-bit (arm64,
# or x86_64 on the simulator), where a 64-bit std::atomic is lock-free in
# hardware and needs no libatomic. Revisit only if a 32-bit Apple target returns.
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(LIBRATS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(LIBRATS_BINARY_DIR ${CMAKE_BINARY_DIR}/librats_native)

if(NOT EXISTS "${LIBRATS_SOURCE_DIR}/CMakeLists.txt")
    message(FATAL_ERROR
        "librats root CMakeLists.txt not found at ${LIBRATS_SOURCE_DIR}. "
        "Build the iOS module from within the repository.")
endif()

# Options for the iOS cross-compile. A static library is deliberate: it links
# straight into the app binary, so there is no embedded dylib to code-sign and
# no dynamic-loader work at launch.
set(RATS_BUILD_CLIENT    OFF CACHE BOOL "No rats-client executable on iOS"    FORCE)
set(RATS_BUILD_EXAMPLES  OFF CACHE BOOL "No examples on iOS"                  FORCE)
set(RATS_BUILD_TESTS     OFF CACHE BOOL "GoogleTest host binaries cannot run on-device" FORCE)
set(RATS_CROSSCOMPILING  ON  CACHE BOOL "Cross-compiling to iOS"              FORCE)
set(RATS_BINDINGS        ON  CACHE BOOL "The C ABI is what Swift imports"      FORCE)
set(RATS_STATIC_LIBRARY  ON  CACHE BOOL "Static: no dylib to sign or embed"    FORCE)
set(RATS_SHARED_LIBRARY  OFF CACHE BOOL ""                                     FORCE)

# The distributed key-value store is off by default in the root build; the React
# Native binding exposes it, so it has to be on here or the storage symbols do not
# exist to link against.
set(RATS_STORAGE       ON  CACHE BOOL "Storage is part of this binding's API" FORCE)
# BitTorrent is on because enableBittorrent() is part of this binding's API. Its cost
# is 0.5 MB on a stripped arm64 release build of librats (2.73 -> 3.25 MB) — measure
# stripped, not the ~10 MB the unstripped debug artifacts differ by. Drop this and the
# spec's BitTorrent methods together if that still matters more than the feature.
set(RATS_SEARCH_FEATURES ON  CACHE BOOL "BitTorrent is part of this binding's API" FORCE)

# Install rules stay ON: `cmake --install` is how the header tree (including the
# generated version.h / features.h) is staged for the XCFramework.
set(RATS_INSTALL         ON  CACHE BOOL "Staged into the XCFramework"          FORCE)

add_subdirectory(${LIBRATS_SOURCE_DIR} ${LIBRATS_BINARY_DIR})

if(NOT TARGET rats)
    message(FATAL_ERROR "librats target 'rats' was not created by the root CMakeLists.txt")
endif()

# Bitcode has been removed from Xcode and is rejected by the App Store; make sure
# nothing re-adds it. `-fembed-bitcode` would also conflict with the static
# archive we hand to xcodebuild -create-xcframework.
set_target_properties(rats PROPERTIES
    XCODE_ATTRIBUTE_ENABLE_BITCODE NO
)

# The module map lets Swift `import LibRats` against the C ABI directly — no
# Objective-C or C++ shim layer, which is the whole reason the iOS binding is
# smaller than the JNI one. Staged next to the headers it describes, because
# clang resolves a module map's header paths relative to the map's own directory.
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/module.modulemap
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

message(STATUS "librats iOS: ${CMAKE_OSX_SYSROOT} arch=${CMAKE_OSX_ARCHITECTURES} "
               "min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
