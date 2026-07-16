cmake_minimum_required(VERSION 3.22.1)

project("librats_android")

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Android system libraries: liblog for __android_log_print. Socket/networking
# symbols are part of Bionic libc (no separate lib to link). The core 'rats'
# target links any Android-specific helpers itself (see the root CMakeLists.txt
# ANDROID branch — ifaddrs shim for API < 24).
find_library(log-lib log)
find_package(Threads REQUIRED)

# Build the core LibRats library by pulling in the repository-root CMake. That
# CMakeLists defines LIBRARY_SOURCES (core, util, wire, transport, peer,
# security, node, subsystems, dht, mdns, crypto, nat) plus the C ABI under
# src/bindings/rats.{h,cpp} when RATS_BINDINGS is ON, and configures the
# generated version.h. We do not duplicate the source list here.
set(LIBRATS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../../../../)
set(LIBRATS_BINARY_DIR ${CMAKE_BINARY_DIR}/librats_native)

if(EXISTS "${LIBRATS_SOURCE_DIR}/CMakeLists.txt")
    # Options suitable for Android cross-compilation.
    set(RATS_BUILD_CLIENT OFF CACHE BOOL "Disable the rats-client executable for Android build" FORCE)
    set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "Disable examples for Android build" FORCE)
    set(RATS_BUILD_TESTS OFF CACHE BOOL "Disable tests for Android build" FORCE)
    set(RATS_CROSSCOMPILING ON CACHE BOOL "Indicate cross-compilation environment" FORCE)
    set(RATS_BINDINGS ON CACHE BOOL "Enable the C ABI (src/bindings/rats.cpp) for JNI" FORCE)
    set(RATS_INSTALL OFF CACHE BOOL "Skip install rules for Android build" FORCE)

    add_subdirectory(${LIBRATS_SOURCE_DIR} ${LIBRATS_BINARY_DIR})

    if(TARGET rats)
        target_compile_definitions(rats PRIVATE ANDROID __ANDROID__)
    else()
        message(FATAL_ERROR "LibRats target 'rats' was not created by root CMakeLists.txt")
    endif()

    # JNI bridge to the C ABI.
    add_library(rats_jni SHARED librats_jni.cpp)

    # Public headers (src/, with rats.h reachable as "bindings/rats.h") and the
    # generated version.h (under <binary>/src/util/version.h).
    target_include_directories(rats_jni PRIVATE
        ${LIBRATS_SOURCE_DIR}/src
        ${LIBRATS_BINARY_DIR}/src
    )

    # Link the JNI bridge against the core library and Android liblog.
    target_link_libraries(rats_jni
        rats
        ${log-lib}
    )

    target_compile_options(rats_jni PRIVATE
        -fvisibility=default
        -fPIC
        -O2
        -Wall
        -Wextra
        -Wno-unused-parameter
        -Wno-missing-field-initializers
    )

    set_target_properties(rats_jni PROPERTIES
        ANDROID_ARM_NEON TRUE
        LINK_FLAGS "-Wl,--export-dynamic"
    )
else()
    message(FATAL_ERROR "LibRats root CMakeLists.txt not found at ${LIBRATS_SOURCE_DIR}. Build the Android module from the repository so native sources are available.")
endif()
