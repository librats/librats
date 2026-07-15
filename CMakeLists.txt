cmake_minimum_required(VERSION 3.14)

# Allow consumers (vcpkg/Conan/source tarballs) to bypass git lookup by
# passing -DRATS_VERSION_OVERRIDE=X.Y.Z on the configure line.
if(DEFINED RATS_VERSION_OVERRIDE AND RATS_VERSION_OVERRIDE MATCHES "^([0-9]+)\\.([0-9]+)\\.([0-9]+)$")
    set(VERSION_MAJOR ${CMAKE_MATCH_1})
    set(VERSION_MINOR ${CMAKE_MATCH_2})
    set(VERSION_PATCH ${CMAKE_MATCH_3})
    set(GIT_DESCRIBE "${RATS_VERSION_OVERRIDE}")
    set(GIT_REVISION_COUNT 0)
else()
    # Get version from git
    find_package(Git QUIET)
    if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
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
        # Fallback when git is not available (e.g. source tarball builds)
        set(VERSION_MAJOR 1)
        set(VERSION_MINOR 0)
        set(VERSION_PATCH 0)
        set(GIT_DESCRIBE "unknown")
        set(GIT_REVISION_COUNT 0)
    endif()
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
    ${PROJECT_SOURCE_DIR}/src/util/version.h.in
    ${PROJECT_BINARY_DIR}/src/util/version.h
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

# Define library sources, grouped by subsystem (mirrors the src/ layout)
set(LIBRARY_SOURCES
# core/ — sockets, async I/O buffers, platform I/O multiplexing, reactor primitives
    src/core/socket.h
    src/core/socket.cpp
    src/core/receive_buffer.h
    src/core/receive_buffer.cpp
    src/core/chained_send_buffer.h
    src/core/chained_send_buffer.cpp
    src/core/io_poller.h
    src/core/io_poller.cpp
    src/core/bytes.h
    src/core/address.h
    src/core/address.cpp
    src/core/ip_address.h
    src/core/ip_address.cpp
    src/core/host_endpoint.h
    src/core/endpoint_parse.h
    src/core/endpoint_parse.cpp
    src/core/types.h
    src/core/types.cpp
    src/core/mpsc_queue.h
    src/core/timer_queue.h
    src/core/notifier.h
    src/core/event_bus.h
    src/core/service_registry.h

# util/ — networking helpers, OS/filesystem, logging, version
    src/util/network_utils.h
    src/util/network_utils.cpp
    src/util/network_monitor.h
    src/util/network_monitor.cpp
    src/util/os.h
    src/util/os.cpp
    src/util/fs.h
    src/util/fs.cpp
    src/util/logger.h
    src/util/logger.cpp
    src/util/json.h
    src/util/json.cpp
    src/util/version.cpp
    src/util/rats_export.h
    ${PROJECT_BINARY_DIR}/src/util/version.h

# wire/ — length-prefixed frame format + type-routed dispatch
    src/wire/frame.h
    src/wire/frame.cpp
    src/wire/message_router.h
    src/wire/message_router.cpp

# transport/ — shared-nothing reactor, per-connection state machine
    src/transport/connection.h
    src/transport/connection.cpp
    src/transport/reactor.h
    src/transport/reactor.cpp
    src/transport/reactor_pool.h

# peer/ — self-certifying peer ids, routing/connection tables
    src/peer/peer_id.h
    src/peer/peer_id.cpp
    src/peer/peer_info.h
    src/peer/peer.h
    src/peer/peer_table.h
    src/peer/peer_table.cpp
    src/peer/peer_book.h
    src/peer/peer_book.cpp

# security/ — Noise XX / plaintext over a self-certifying identity
    src/security/session.h
    src/security/identity.h
    src/security/handshaker.h
    src/security/noise_security.h
    src/security/noise_security.cpp
    src/security/plaintext_security.h

# node/ — node facade, peer-network contract, identify handshake
    src/node/config.h
    src/node/host_events.h
    src/node/node_context.h
    src/node/peer_network.h
    src/node/node.h
    src/node/node.cpp
    src/node/identify.h
    src/node/identify.cpp

# subsystems/ — opt-in plugins attached to a Node
    src/subsystems/ping_service.h
    src/subsystems/ping_service.cpp
    src/subsystems/pubsub.h
    src/subsystems/pubsub.cpp
    src/subsystems/message_json.h
    src/subsystems/message_json.cpp
    src/subsystems/file_transfer.h
    src/subsystems/file_transfer.cpp
    src/subsystems/dht_service.h
    src/subsystems/dht_discovery.h
    src/subsystems/dht_discovery.cpp
    src/subsystems/mdns_discovery.h
    src/subsystems/mdns_discovery.cpp
    src/subsystems/reconnection.h
    src/subsystems/reconnection.cpp
    src/subsystems/peer_exchange.h
    src/subsystems/peer_exchange.cpp
    src/subsystems/port_mapping_service.h
    src/subsystems/port_mapping_service.cpp

# dht/ — Kademlia DHT + KRPC (bencode is shared with bittorrent, always built)
    src/dht/dht.h
    src/dht/dht.cpp
    src/dht/krpc.h
    src/dht/krpc.cpp
# dht/ modular layer (rewrite in progress) — leaf types
    src/dht/id.h
    src/dht/log.h
    src/dht/node_entry.h
    src/dht/bep42.h
    src/dht/bep42.cpp
    src/dht/routing_table.h
    src/dht/routing_table.cpp
    src/dht/transport.h
    src/dht/observer.h
    src/dht/rpc_manager.h
    src/dht/rpc_manager.cpp
    src/dht/traversal.h
    src/dht/traversal.cpp
    src/dht/find_peers.h
    src/dht/find_peers.cpp
    src/dht/announce.h
    src/dht/announce.cpp
    src/dht/storage.h
    src/dht/storage.cpp
    src/dht/dos_blocker.h
    src/dht/dos_blocker.cpp
    src/dht/node.h
    src/dht/node.cpp
    src/dht/udp_transport.h
    src/dht/udp_transport.cpp
    src/dht/dht_runner.h
    src/dht/dht_runner.cpp
    src/dht/persistence.h
    src/dht/persistence.cpp
    src/bittorrent/bencode.h
    src/bittorrent/bencode.cpp

# mdns/ — local-network service discovery
    src/mdns/mdns.h
    src/mdns/mdns.cpp

# crypto/ — hashes, ciphers, KDFs
    src/crypto/sha1.h
    src/crypto/sha1.cpp
    src/crypto/crc32.h
    src/crypto/crc32.cpp
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

# crypto/ — Noise Protocol framework (Noise_XX transport encryption)
    src/crypto/noise.cpp
    src/crypto/noise.h

# nat/ — STUN public-IP discovery + UPnP IGD / NAT-PMP port forwarding
    src/nat/stun.h
    src/nat/stun.cpp
    src/nat/port_mapping.h
    src/nat/upnp.h
    src/nat/upnp.cpp
    src/nat/natpmp.h
    src/nat/natpmp.cpp
)

# Add BitTorrent sources if RATS_SEARCH_FEATURES is enabled
if(RATS_SEARCH_FEATURES)
    list(APPEND LIBRARY_SOURCES
        src/bittorrent/types.h
        src/bittorrent/types.cpp
        src/bittorrent/byte_io.h
        src/bittorrent/bitfield.h
        src/bittorrent/bitfield.cpp
        src/bittorrent/file_storage.h
        src/bittorrent/file_storage.cpp
        src/bittorrent/magnet_uri.h
        src/bittorrent/magnet_uri.cpp
        src/bittorrent/torrent_info.h
        src/bittorrent/torrent_info.cpp
        src/bittorrent/store_buffer.h
        src/bittorrent/store_buffer.cpp
        src/bittorrent/disk_io.h
        src/bittorrent/disk_io.cpp
        src/bittorrent/piece_picker.h
        src/bittorrent/piece_picker.cpp
        src/bittorrent/reactor.h
        src/bittorrent/reactor.cpp
        src/bittorrent/peer_connection.h
        src/bittorrent/peer_connection.cpp
        src/bittorrent/choker.h
        src/bittorrent/choker.cpp
        src/bittorrent/torrent.h
        src/bittorrent/torrent.cpp
        src/bittorrent/client.h
        src/bittorrent/client.cpp
        src/bittorrent/extensions.h
        src/bittorrent/extensions.cpp
        src/bittorrent/peer_list.h
        src/bittorrent/peer_list.cpp
        src/bittorrent/tracker.h
        src/bittorrent/tracker.cpp
        src/bittorrent/resume_data.h
        src/bittorrent/resume_data.cpp
        src/bittorrent/torrent_creator.h
        src/bittorrent/torrent_creator.cpp
        src/subsystems/bittorrent.h
        src/subsystems/bittorrent.cpp
    )
endif()

# Add Storage sources if RATS_STORAGE is enabled
# StorageManager is a Node subsystem (reaches the mesh via PeerNetwork).
if(RATS_STORAGE)
    list(APPEND LIBRARY_SOURCES
        src/storage/storage.cpp
        src/storage/storage.h
    )
endif()

if(RATS_BINDINGS)
    list(APPEND LIBRARY_SOURCES
        src/bindings/rats.h
        src/bindings/rats.cpp
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

# GNUInstallDirs supplies CMAKE_INSTALL_INCLUDEDIR / LIBDIR / BINDIR. Include
# it unconditionally so the INSTALL_INTERFACE generator expression below
# resolves correctly even when RATS_INSTALL is later disabled.
include(GNUInstallDirs)

# Include directories. INSTALL_INTERFACE entries are only consumed via the
# exported target, so they are safe to declare even when RATS_INSTALL is OFF.
target_include_directories(rats
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/crypto>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/src>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/librats>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/librats/crypto>
)

# Find and link threading support
find_package(Threads REQUIRED)
target_link_libraries(rats Threads::Threads)

# 64-bit atomics: on 32-bit targets (e.g. ppc, armv7, x86, mips) an 8-byte
# std::atomic is not lock-free in hardware, so the compiler lowers it to
# __atomic_*_8 libcalls that live in libatomic. Detect that case and link it,
# otherwise the link fails with "undefined ___atomic_fetch_add_8" etc.
include(CheckCXXSourceCompiles)
set(CMAKE_REQUIRED_FLAGS "${CMAKE_CXX_FLAGS}")
check_cxx_source_compiles("
#include <atomic>
#include <cstdint>
std::atomic<uint64_t> x;
int main() { x.fetch_add(1); x.store(2); return (int)x.load(); }
" HAVE_BUILTIN_ATOMIC64)
unset(CMAKE_REQUIRED_FLAGS)
if(NOT HAVE_BUILTIN_ATOMIC64)
    target_link_libraries(rats atomic)
endif()

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
        tests/test_ip_address.cpp
        tests/test_bencode.cpp
        tests/test_sha1.cpp
        tests/test_network_utils.cpp
        tests/test_dht.cpp
        tests/test_dht_id.cpp
        tests/test_dht_bootstrap.cpp
        tests/test_dht_bep42.cpp
        tests/test_dht_node_entry.cpp
        tests/test_dht_routing_table.cpp
        tests/test_dht_ip_diversity.cpp
        tests/test_dht_rpc_manager.cpp
        tests/test_dht_traversal.cpp
        tests/test_dht_storage.cpp
        tests/test_dht_node.cpp
        tests/test_dht_persistence_v2.cpp
        tests/test_dht_udp.cpp
        tests/test_os.cpp
        tests/test_fs.cpp
        tests/test_json.cpp
        tests/test_main.cpp
# Noise Protocol Crypto tests
        tests/test_crypto_curve25519.cpp
        tests/test_crypto_chacha_poly.cpp
        tests/test_crypto_sha2.cpp
        tests/test_crypto_blake2.cpp
        tests/test_noise.cpp
# NAT traversal tests (STUN)
        tests/test_stun.cpp
# Automatic port forwarding tests (UPnP/NAT-PMP)
        tests/test_portmap.cpp
# Network change detection tests
        tests/test_network_monitor.cpp
# I/O poller abstraction (epoll/kqueue/IOCP)
        tests/test_io_poller.cpp
# Buffer utilities for file transfer and bittorrent
        tests/test_receive_buffer.cpp
        tests/test_chained_send_buffer.cpp
# Wire framing, reactor transport, node + subsystems
        tests/test_frame.cpp
        tests/test_reactor.cpp
        tests/test_handshake.cpp
        tests/test_node.cpp
        tests/test_identify.cpp
        tests/test_persistence.cpp
        tests/test_event_bus.cpp
        tests/test_subsystem.cpp
        tests/test_pubsub.cpp
        tests/test_peer_exchange.cpp
        tests/test_message_json.cpp
        tests/test_filexfer.cpp
        tests/test_dht_discovery.cpp
        tests/test_reconnection.cpp
        tests/test_logging.cpp
    )

    # Add BitTorrent tests if RATS_SEARCH_FEATURES is enabled
    if(RATS_SEARCH_FEATURES)
        list(APPEND TEST_SOURCES
            # Phase 0 — primitives
            tests/test_bt_types.cpp
            tests/test_bt_byte_io.cpp
            tests/test_bt_bitfield.cpp
            # Phase 1 — metadata
            tests/test_bt_file_storage.cpp
            tests/test_bt_magnet.cpp
            tests/test_bt_torrent_info.cpp
            # Phase 2 — disk I/O
            tests/test_bt_store_buffer.cpp
            tests/test_bt_disk_io.cpp
            # Phase 3 — piece picker
            tests/test_bt_piece_picker.cpp
            # Phase 4 — reactor + peer wire protocol
            tests/test_bt_reactor.cpp
            tests/test_bt_peer_connection.cpp
            # Phase 5 — torrent + client + choker
            tests/test_bt_choker.cpp
            tests/test_bt_download.cpp
            tests/test_bt_stall_metadata.cpp
            # Phase 6 — extension protocol + metadata exchange + discovery
            tests/test_bt_extensions.cpp
            tests/test_bt_magnet_fetch.cpp
            tests/test_bt_peer_list.cpp
            tests/test_bt_pex.cpp
            tests/test_bt_tracker.cpp
            # Phase 7 — fast resume + torrent creation
            tests/test_bt_resume_data.cpp
            tests/test_bt_pause_resume.cpp
            tests/test_bt_torrent_creator.cpp
            # Phase 8 — node subsystem integration
            tests/test_bt_subsystem.cpp
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
            tests/test_node_capi.cpp
        )
    endif()
    
    # Add mDNS tests only on non-macOS platforms
    if(NOT APPLE)
        list(APPEND TEST_SOURCES tests/test_mdns.cpp)
        list(APPEND TEST_SOURCES tests/test_mdns_discovery.cpp)
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

# -----------------------------------------------------------------------------
# Install / export configuration (consumed by vcpkg, Conan, and find_package)
# -----------------------------------------------------------------------------
option(RATS_INSTALL "Generate install rules and package config" ON)

if(RATS_INSTALL)
    include(CMakePackageConfigHelpers)

    install(TARGETS rats
        EXPORT ratsTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/librats
    )

    # Headers form a tightly coupled graph (librats.h pulls in dht/krpc/bencode/
    # bt_*/storage/io_poller/etc.), so install the whole header tree under
    # include/librats/. .cpp / .c / .in files are excluded.
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/src/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/librats
        FILES_MATCHING
            PATTERN "*.h"
            PATTERN "*.hpp"
    )
    install(FILES ${PROJECT_BINARY_DIR}/src/util/version.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/librats
    )

    install(EXPORT ratsTargets
        FILE ratsTargets.cmake
        NAMESPACE rats::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rats
    )

    configure_package_config_file(
        ${PROJECT_SOURCE_DIR}/cmake/ratsConfig.cmake.in
        ${PROJECT_BINARY_DIR}/cmake/ratsConfig.cmake
        INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rats
    )
    write_basic_package_version_file(
        ${PROJECT_BINARY_DIR}/cmake/ratsConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(FILES
        ${PROJECT_BINARY_DIR}/cmake/ratsConfig.cmake
        ${PROJECT_BINARY_DIR}/cmake/ratsConfigVersion.cmake
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/rats
    )
endif()