cmake_minimum_required(VERSION 3.18.1)

project("librats_android")

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find required packages
find_library(log-lib log)
find_package(Threads REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/../../../src)

# Add all librats source files
set(LIBRATS_SOURCES
    ${CMAKE_SOURCE_DIR}/../../../src/bencode.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/bittorrent.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/dht.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/encrypted_socket.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/file_transfer.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/fs.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/gossipsub.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/ice.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/krpc.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_c.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_encryption.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_file_transfer.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_gossipsub.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_ice.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_logging.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_mdns.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_nat.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats_persistence.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/librats.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/mdns.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/network_utils.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/noise.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/os.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/sha1.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/socket.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/stun.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/threadmanager.cpp
    ${CMAKE_SOURCE_DIR}/../../../src/version.cpp
)

# Create the main librats library
add_library(rats SHARED ${LIBRATS_SOURCES})

# Set compile definitions for librats
target_compile_definitions(rats PRIVATE
    RATS_BUILDING_DLL
    ANDROID
    __ANDROID__
)

# Link libraries for librats
target_link_libraries(rats
    ${log-lib}
    Threads::Threads
)

# Add JNI wrapper library
add_library(rats_jni SHARED librats_jni.cpp)

# Link JNI wrapper with librats and required libraries
target_link_libraries(rats_jni
    rats
    ${log-lib}
    Threads::Threads
)

# Set properties for both libraries
set_target_properties(rats PROPERTIES
    ANDROID_ARM_NEON TRUE
)

set_target_properties(rats_jni PROPERTIES
    ANDROID_ARM_NEON TRUE
)

# Compiler flags for optimization and Android compatibility
target_compile_options(rats PRIVATE
    -fvisibility=default
    -fPIC
    -O2
    -Wall
    -Wextra
    -Wno-unused-parameter
    -Wno-missing-field-initializers
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

# Platform-specific configurations
if(ANDROID_ABI STREQUAL "arm64-v8a")
    target_compile_definitions(rats PRIVATE __ARM_NEON__)
    target_compile_definitions(rats_jni PRIVATE __ARM_NEON__)
elseif(ANDROID_ABI STREQUAL "armeabi-v7a")
    target_compile_definitions(rats PRIVATE __ARM_NEON__)
    target_compile_definitions(rats_jni PRIVATE __ARM_NEON__)
endif()

# Export symbols for JNI
set_target_properties(rats_jni PROPERTIES
    LINK_FLAGS "-Wl,--export-dynamic"
)
