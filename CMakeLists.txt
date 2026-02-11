cmake_minimum_required(VERSION 3.10)

# Get version from git
find_package(Git QUIET)
if(GIT_FOUND)
    # Get the current git tag/commit
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    # Extract version from git tag (format: v1.2.3 or 1.2.3)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_TAG
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    # Get commit count (revision number)
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-list --count HEAD
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
        OUTPUT_VARIABLE GIT_REVISION_COUNT
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
    )
    
    # Parse version components
    if(GIT_TAG MATCHES "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)")
        set(VERSION_MAJOR ${CMAKE_MATCH_1})
        set(VERSION_MINOR ${CMAKE_MATCH_2})
        set(VERSION_PATCH ${CMAKE_MATCH_3})
    else()
        # Fallback to default version
        set(VERSION_MAJOR 1)
        set(VERSION_MINOR 0)
        set(VERSION_PATCH 0)
    endif()
else()
    # Fallback when git is not available
    set(VERSION_MAJOR 1)
    set(VERSION_MINOR 0)
    set(VERSION_PATCH 0)
    set(GIT_DESCRIBE "unknown")
    set(GIT_REVISION_COUNT 0)
endif()

# Set build number to revision count (commit count)
if(GIT_REVISION_COUNT)
    set(VERSION_BUILD ${GIT_REVISION_COUNT})
else()
    set(VERSION_BUILD 0)
endif()
set(VERSION_STRING "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}.${VERSION_BUILD}")

# Set project version from git
project(librats VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Flags
# Compiler warnings configuration
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    # additional checks by compiler to found errors ealy on
    add_compile_options(-Wall -Wextra -Wpedantic)
    # not show unused stuff, useful for development
    add_compile_options(-Wno-unused-parameter -Wno-unused-variable -Wno-unused-but-set-variable)
endif()

# Options
option(RATS_BUILD_EXAMPLES "Build examples" ON)
option(RATS_BUILD_TESTS "Build unit tests" ON)
option(RATS_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(RATS_ENABLE_TSAN "Enable ThreadSanitizer" OFF)
option(RATS_BINDINGS "Enable bindings" ON)
option(RATS_CROSSCOMPILING "Force cross-compilation flags" OFF)
option(RATS_SHARED_LIBRARY "Build as shared library" OFF)
option(RATS_STATIC_LIBRARY "Build as static library" ON)
option(RATS_SEARCH_FEATURES "Features related to rats-search project (like bittorrent)" OFF)
option(RATS_STORAGE "Enable distributed storage module" OFF)

# Validate library type options
if(RATS_SHARED_LIBRARY AND RATS_STATIC_LIBRARY)
    message(WARNING "Both RATS_SHARED_LIBRARY and RATS_STATIC_LIBRARY are enabled. Defaulting to shared library.")
    set(RATS_STATIC_LIBRARY OFF)
elseif(NOT RATS_SHARED_LIBRARY AND NOT RATS_STATIC_LIBRARY)
    message(WARNING "Neither RATS_SHARED_LIBRARY nor RATS_STATIC_LIBRARY are enabled. Defaulting to static library.")
    set(RATS_STATIC_LIBRARY ON)
endif()

# Disable tests when building shared library
if(RATS_SHARED_LIBRARY AND RATS_BUILD_TESTS)
    message(STATUS "Disabling tests when building shared library.")
    set(RATS_BUILD_TESTS OFF)
endif()

# Configure version.h from template
configure_file(
    ${PROJECT_SOURCE_DIR}/src/version.h.in
    ${PROJECT_BINARY_DIR}/src/version.h
    @ONLY
)

# Configure version.rc from template
if(WIN32)
    configure_file(
        ${PROJECT_SOURCE_DIR}/version.rc.in
        ${PROJECT_BINARY_DIR}/version.rc
        @ONLY
    )
endif()

# Define library sources
set(LIBRARY_SOURCES
    src/socket.cpp
    src/socket.h
    src/network_utils.cpp
    src/network_utils.h
    src/dht.cpp
    src/dht.h
    src/bencode.cpp
    src/bencode.h
    src/krpc.cpp
    src/krpc.h
    src/librats.cpp
    src/librats_reconnection.cpp
    src/librats_logging.cpp
    src/librats_encryption.cpp
    src/librats_file_transfer.cpp
    src/librats_gossipsub.cpp
    src/librats_mdns.cpp
    src/librats_persistence.cpp
    src/librats.h
    src/sha1.cpp
    src/sha1.h
    src/os.cpp
    src/os.h
    src/fs.cpp
    src/fs.h
    src/logger.h
    src/logger.cpp
    src/mdns.cpp
    src/mdns.h
    src/threadmanager.cpp
    src/threadmanager.h
    src/gossipsub.cpp
    src/gossipsub.h
    src/file_transfer.cpp
    src/file_transfer.h
    src/version.cpp
    src/rats_export.h
    ${PROJECT_BINARY_DIR}/src/version.h

# Buffer utilities for async I/O, file transfer, and bittorrent
    src/receive_buffer.h
    src/receive_buffer.cpp
    src/chained_send_buffer.h
    src/chained_send_buffer.cpp

# Platform-optimal I/O multiplexing (epoll/kqueue/IOCP)
    src/io_poller.h
    src/io_poller.cpp

# Crypto algorithms including Noise Protocol
    src/crypto/curve25519.c
    src/crypto/curve25519.h
    src/crypto/chacha.c
    src/crypto/chacha.h
    src/crypto/poly1305.c
    src/crypto/poly1305.h
    src/crypto/chachapoly.c
    src/crypto/chachapoly.h
    src/crypto/sha256.c
    src/crypto/sha256.h
    src/crypto/sha512.c
    src/crypto/sha512.h
    src/crypto/hkdf.c
    src/crypto/hkdf.h
    src/crypto/blake2s.c
    src/crypto/blake2s.h
    src/crypto/blake2b.c
    src/crypto/blake2b.h
    src/crypto/blake2_endian.h

# Noise Protocol implementation
    src/noise.cpp
    src/noise.h

# NAT traversal (STUN/TURN/ICE)
    src/stun.cpp
    src/stun.h
    src/turn.cpp
    src/turn.h
    src/ice.cpp
    src/ice.h
    src/librats_ice.cpp
)

# Add BitTorrent sources if RATS_SEARCH_FEATURES is enabled
if(RATS_SEARCH_FEATURES)
    list(APPEND LIBRARY_SOURCES
        src/librats_bittorrent.cpp
        src/bittorrent.cpp
        src/bittorrent.h
        src/bt_types.h
        src/bt_bitfield.h
        src/bt_bitfield.cpp
        src/bt_file_storage.h
        src/bt_file_storage.cpp
        src/bt_torrent_info.h
        src/bt_torrent_info.cpp
        src/bt_piece_picker.h
        src/bt_piece_picker.cpp
        src/bt_messages.h
        src/bt_messages.cpp
        src/bt_handshake.h
        src/bt_handshake.cpp
        src/bt_peer_connection.h
        src/bt_peer_connection.cpp
        src/bt_extension.h
        src/bt_extension.cpp
        src/bt_choker.h
        src/bt_choker.cpp
        src/bt_torrent.h
        src/bt_torrent.cpp
        src/bt_client.h
        src/bt_client.cpp
        src/bt_network.h
        src/bt_network.cpp
        src/disk_io.cpp
        src/disk_io.h
        src/tracker.cpp
        src/tracker.h
        src/bt_create_torrent.h
        src/bt_create_torrent.cpp
        src/bt_resume_data.h
        src/bt_resume_data.cpp
    )
endif()

# Add Storage sources if RATS_STORAGE is enabled
if(RATS_STORAGE)
    list(APPEND LIBRARY_SOURCES
        src/crc32.cpp
        src/crc32.h
        src/storage.cpp
        src/storage.h
        src/librats_storage.cpp
    )
endif()

if(RATS_BINDINGS)
    list(APPEND LIBRARY_SOURCES 
        src/librats_c.cpp
        src/librats_c.h
    )
endif()

# Create library with appropriate type
if(RATS_SHARED_LIBRARY)
    add_library(rats SHARED ${LIBRARY_SOURCES})
    set_target_properties(rats PROPERTIES
        VERSION ${VERSION_STRING}
        SOVERSION ${VERSION_MAJOR}
    )
    target_compile_definitions(rats PRIVATE RATS_EXPORT_DLL)
else()
    add_library(rats STATIC ${LIBRARY_SOURCES})
endif()

# Enable Position Independent Code for static library (required for linking into shared objects)
set_target_properties(rats PROPERTIES POSITION_INDEPENDENT_CODE ON)

# Include directories
target_include_directories(rats PUBLIC ${PROJECT_BINARY_DIR}/src src)
target_include_directories(rats PUBLIC ${PROJECT_SOURCE_DIR}/src/crypto)

# Find and link threading support
find_package(Threads REQUIRED)
target_link_libraries(rats Threads::Threads)

# Link networking libraries
if(WIN32)
    target_link_libraries(rats ws2_32 iphlpapi bcrypt)
endif()

if(ANDROID)
    if(DEFINED ANDROID_PLATFORM)
        string(REGEX REPLACE "android-" "" ANDROID_API_LEVEL ${ANDROID_PLATFORM})
        math(EXPR ANDROID_API_LEVEL "${ANDROID_API_LEVEL}")
        message(STATUS "Android API level detected: ${ANDROID_API_LEVEL}")
    else()
        message(FATAL_ERROR "ANDROID_PLATFORM is not defined!")
    endif()

    if(ANDROID_API_LEVEL LESS 24)
        target_sources(rats PRIVATE ${PROJECT_SOURCE_DIR}/3rdparty/android/ifaddrs-android.c)
        target_include_directories(rats
            PRIVATE
            ${PROJECT_SOURCE_DIR}/3rdparty/android
        )
        target_compile_definitions(rats PUBLIC RATS_ANDROID_OLD_API)
        message(STATUS "Using ifaddrs-android for backward compatibility")
    endif()
endif()

if(RATS_SEARCH_FEATURES)
    message(STATUS "Enable rats-search features")
    target_compile_definitions(rats PUBLIC RATS_SEARCH_FEATURES)
endif(RATS_SEARCH_FEATURES)

if(RATS_STORAGE)
    message(STATUS "Enable distributed storage module")
    target_compile_definitions(rats PUBLIC RATS_STORAGE)
endif(RATS_STORAGE)

# Create the main executable
if(RATS_BUILD_EXAMPLES)
    add_executable(rats-client src/main.cpp)
    target_link_libraries(rats-client rats)

    # Add version information to help reduce false positives (Windows only)
    if(WIN32 AND EXISTS "${PROJECT_SOURCE_DIR}/version.rc.in")
        set(VERSION_RC "${PROJECT_BINARY_DIR}/version.rc")
        target_sources(rats-client PRIVATE "${VERSION_RC}")
    endif()

    set_target_properties(rats-client PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin
    )
endif()

# Set output directories
set_target_properties(rats PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/lib
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin
)

# Sanitizer configuration - ASAN and TSAN are mutually exclusive
if(RATS_ENABLE_ASAN AND RATS_ENABLE_TSAN)
    message(FATAL_ERROR "AddressSanitizer and ThreadSanitizer cannot be enabled simultaneously")
endif()

# AddressSanitizer configuration
if(RATS_ENABLE_ASAN)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(ASAN_FLAGS "-fsanitize=address -fno-omit-frame-pointer -g")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${ASAN_FLAGS}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${ASAN_FLAGS}")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${ASAN_FLAGS}")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${ASAN_FLAGS}")
        
        message(STATUS "AddressSanitizer enabled (GCC/Clang)")
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /fsanitize=address")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /fsanitize=address")
        
        message(STATUS "AddressSanitizer enabled (MSVC)")
    else()
        message(WARNING "AddressSanitizer is not supported by this compiler")
    endif()
endif()

# ThreadSanitizer configuration
if(RATS_ENABLE_TSAN)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(TSAN_FLAGS "-fsanitize=thread -fno-omit-frame-pointer -g")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${TSAN_FLAGS}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${TSAN_FLAGS}")
        set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${TSAN_FLAGS}")
        set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${TSAN_FLAGS}")
        
        message(STATUS "ThreadSanitizer enabled (GCC/Clang)")
    else()
        message(WARNING "ThreadSanitizer is only supported by GCC/Clang compilers")
    endif()
endif()

if(RATS_BUILD_TESTS)
    target_compile_definitions(rats PUBLIC TESTING)

    # Enable testing
    enable_testing()
    
    # Find GoogleTest
    find_package(GTest QUIET)
    
    if(NOT GTest_FOUND)
        # Download GoogleTest
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.zip
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        
        # For Windows: Prevent overriding the parent project's compiler/linker settings
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        
        FetchContent_MakeAvailable(googletest)
    endif()
    
    # Create test source list
    set(TEST_SOURCES
        tests/test_socket.cpp
        tests/test_bencode.cpp
        tests/test_sha1.cpp
        tests/test_network_utils.cpp
        tests/test_dht.cpp
        tests/test_rats_client.cpp
        tests/test_os.cpp
        tests/test_fs.cpp
        tests/test_config_persistence.cpp
        tests/test_main.cpp
        tests/test_message_exchange.cpp
        tests/test_gossipsub.cpp
        tests/test_logging_api_gtest.cpp
        tests/test_file_transfer.cpp
        tests/test_reconnection.cpp
# Noise Protocol Crypto tests
        tests/test_crypto_curve25519.cpp
        tests/test_crypto_chacha_poly.cpp
        tests/test_crypto_sha2.cpp
        tests/test_crypto_blake2.cpp
        tests/test_noise.cpp
# NAT traversal tests (STUN/TURN/ICE)
        tests/test_stun.cpp
        tests/test_turn.cpp
        tests/test_ice.cpp
# I/O poller abstraction (epoll/kqueue/IOCP)
        tests/test_io_poller.cpp
# Buffer utilities for file transfer and bittorrent
        tests/test_receive_buffer.cpp
        tests/test_chained_send_buffer.cpp
    )

    # Add BitTorrent tests if RATS_SEARCH_FEATURES is enabled
    if(RATS_SEARCH_FEATURES)
        list(APPEND TEST_SOURCES 
            tests/test_bittorrent.cpp
            tests/test_tracker.cpp
            tests/test_disk_io.cpp
            tests/test_bt_bitfield.cpp
            tests/test_bt_file_storage.cpp
            tests/test_bt_torrent_info.cpp
            tests/test_bt_piece_picker.cpp
            tests/test_bt_messages.cpp
            tests/test_bt_handshake.cpp
            tests/test_bt_peer_connection.cpp
            tests/test_bt_extension.cpp
            tests/test_bt_network.cpp
            tests/test_bt_integration.cpp
            tests/test_bt_create_torrent.cpp
            tests/test_bt_resume_data.cpp
        )
    endif()

    # Add Storage tests if RATS_STORAGE is enabled
    if(RATS_STORAGE)
        list(APPEND TEST_SOURCES 
            tests/test_crc32.cpp
            tests/test_storage.cpp
        )
    endif()

    if(RATS_BINDINGS)
        list(APPEND TEST_SOURCES 
            tests/test_librats_c_api.cpp
        )
    endif()
    
    # Add mDNS tests only on non-macOS platforms
    if(NOT APPLE)
        list(APPEND TEST_SOURCES tests/test_mdns.cpp)
    endif()
    
    # Create test executable
    add_executable(librats_tests ${TEST_SOURCES})
    
    # Link with GoogleTest and our library
    target_link_libraries(librats_tests 
        rats 
        gtest 
        gtest_main
        gmock
        gmock_main
    )
    
    # Add test discovery
    include(GoogleTest)
    # When cross-compiling, the host cannot execute target binaries. Skip discovery.
    if(NOT CMAKE_CROSSCOMPILING AND NOT RATS_CROSSCOMPILING)
        gtest_discover_tests(librats_tests)
    else()
        message(STATUS "Skipping gtest_discover_tests during cross-compilation")
    endif()
    
    # Set test output directory
    set_target_properties(librats_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin
    )
endif()

# Examples (basic examples always built; BT examples require RATS_SEARCH_FEATURES)
if(RATS_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()