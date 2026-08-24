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
option(RATS_BUILD_CLIENT "Build the rats-client reference application" ON)
option(RATS_BUILD_EXAMPLES "Build the examples/ programs" OFF)
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
    ${PROJECT_SOURCE_DIR}/src/librats/util/version.h.in
    ${PROJECT_BINARY_DIR}/src/librats/util/version.h
    @ONLY
)

# Configure features.h from template — records how this build was configured, so
# the installed headers describe themselves instead of relying on the consumer's
# build system to repeat the flags. Must come after the RATS_SEARCH_FEATURES /
# RATS_STORAGE options and the shared/static resolution above.
#
# `#cmakedefine RATS_IMPORT_DLL` reads a variable of that name: a consumer of the
# shared build needs __declspec(dllimport) on the public classes, a consumer of
# the static build must NOT have it (it would look for __imp_ symbols that are not
# there). The library's own sources get RATS_EXPORT_DLL PRIVATE, which
# rats_export.h tests first, so dllexport still wins while compiling librats.
set(RATS_IMPORT_DLL ${RATS_SHARED_LIBRARY})
configure_file(
    ${PROJECT_SOURCE_DIR}/src/librats/util/features.h.in
    ${PROJECT_BINARY_DIR}/src/librats/util/features.h
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

# Define library sources, grouped by subsystem (mirrors the src/librats/ layout)
set(LIBRARY_SOURCES
# core/ — sockets, async I/O buffers, platform I/O multiplexing, reactor primitives
    src/librats/core/socket.h
    src/librats/core/socket.cpp
    src/librats/core/receive_buffer.h
    src/librats/core/receive_buffer.cpp
    src/librats/core/chained_send_buffer.h
    src/librats/core/chained_send_buffer.cpp
    src/librats/core/io_poller.h
    src/librats/core/io_poller.cpp
    src/librats/core/bytes.h
    src/librats/core/address.h
    src/librats/core/address.cpp
    src/librats/core/ip_address.h
    src/librats/core/ip_address.cpp
    src/librats/core/host_endpoint.h
    src/librats/core/endpoint_parse.h
    src/librats/core/endpoint_parse.cpp
    src/librats/core/types.h
    src/librats/core/types.cpp
    src/librats/core/mpsc_queue.h
    src/librats/core/timer_queue.h
    src/librats/core/notifier.h
    src/librats/core/event_bus.h
    src/librats/core/service_registry.h

# util/ — networking helpers, OS/filesystem, logging, version
    src/librats/util/network_utils.h
    src/librats/util/network_utils.cpp
    src/librats/util/network_monitor.h
    src/librats/util/network_monitor.cpp
    src/librats/util/os.h
    src/librats/util/os.cpp
    src/librats/util/fs.h
    src/librats/util/fs.cpp
    src/librats/util/logger.h
    src/librats/util/logger.cpp
    src/librats/util/json.h
    src/librats/util/json.cpp
    src/librats/util/version.cpp
    src/librats/util/rats_export.h
    ${PROJECT_BINARY_DIR}/src/librats/util/version.h
    ${PROJECT_BINARY_DIR}/src/librats/util/features.h

# wire/ — length-prefixed frame format + type-routed dispatch
    src/librats/wire/frame.h
    src/librats/wire/frame.cpp
    src/librats/wire/message_router.h
    src/librats/wire/message_router.cpp

# transport/ — shared-nothing reactor, per-connection state machine,
#              interchangeable TCP / reliable-UDP links
    src/librats/transport/link.h
    src/librats/transport/tcp_link.h
    src/librats/transport/tcp_link.cpp
    src/librats/transport/udp_packet.h
    src/librats/transport/udp_packet.cpp
    src/librats/transport/udp_stream.h
    src/librats/transport/udp_stream.cpp
    src/librats/transport/udp_mux.h
    src/librats/transport/udp_mux.cpp
    src/librats/transport/relay_link.h
    src/librats/transport/relay_link.cpp
    src/librats/transport/connection.h
    src/librats/transport/connection.cpp
    src/librats/transport/reactor.h
    src/librats/transport/reactor.cpp
    src/librats/transport/reactor_pool.h

# peer/ — self-certifying peer ids, routing/connection tables
    src/librats/peer/peer_id.h
    src/librats/peer/peer_id.cpp
    src/librats/peer/peer_info.h
    src/librats/peer/peer.h
    src/librats/peer/peer_table.h
    src/librats/peer/peer_table.cpp
    src/librats/peer/peer_book.h
    src/librats/peer/peer_book.cpp

# security/ — Noise XX / plaintext over a self-certifying identity
    src/librats/security/session.h
    src/librats/security/identity.h
    src/librats/security/handshaker.h
    src/librats/security/noise_security.h
    src/librats/security/noise_security.cpp
    src/librats/security/plaintext_security.h

# node/ — node facade, peer-network contract, identify handshake
    src/librats/node/config.h
    src/librats/node/host_events.h
    src/librats/node/node_context.h
    src/librats/node/peer_network.h
    src/librats/node/node.h
    src/librats/node/node.cpp
    src/librats/node/identify.h
    src/librats/node/identify.cpp
    src/librats/node/dialer.h
    src/librats/node/dialer.cpp
    src/librats/node/dial_service.h
    src/librats/node/circuit_service.h
    src/librats/node/nat_status.h
    src/librats/node/nat_status.cpp

# subsystems/ — opt-in plugins attached to a Node
    src/librats/subsystems/ping_service.h
    src/librats/subsystems/ping_service.cpp
    src/librats/subsystems/pubsub.h
    src/librats/subsystems/pubsub.cpp
    src/librats/subsystems/message_json.h
    src/librats/subsystems/message_json.cpp
    src/librats/subsystems/file_transfer.h
    src/librats/subsystems/file_transfer.cpp
    src/librats/subsystems/dht_service.h
    src/librats/subsystems/dht_discovery.h
    src/librats/subsystems/dht_discovery.cpp
    src/librats/subsystems/mdns_discovery.h
    src/librats/subsystems/mdns_discovery.cpp
    src/librats/subsystems/reconnection.h
    src/librats/subsystems/reconnection.cpp
    src/librats/subsystems/peer_exchange.h
    src/librats/subsystems/peer_exchange.cpp
    src/librats/subsystems/port_mapping_service.h
    src/librats/subsystems/port_mapping_service.cpp
    src/librats/subsystems/hole_punch.h
    src/librats/subsystems/hole_punch.cpp
    src/librats/subsystems/hole_punch_service.h
    src/librats/subsystems/relay.h
    src/librats/subsystems/relay.cpp
    src/librats/subsystems/relay_service.h

# dht/ — Kademlia DHT + KRPC (bencode is shared with bittorrent, always built)
    src/librats/dht/dht.h
    src/librats/dht/dht.cpp
    src/librats/dht/krpc.h
    src/librats/dht/krpc.cpp
# dht/ modular layer (rewrite in progress) — leaf types
    src/librats/dht/id.h
    src/librats/dht/log.h
    src/librats/dht/node_entry.h
    src/librats/dht/bep42.h
    src/librats/dht/bep42.cpp
    src/librats/dht/routing_table.h
    src/librats/dht/routing_table.cpp
    src/librats/dht/transport.h
    src/librats/dht/observer.h
    src/librats/dht/rpc_manager.h
    src/librats/dht/rpc_manager.cpp
    src/librats/dht/traversal.h
    src/librats/dht/traversal.cpp
    src/librats/dht/find_peers.h
    src/librats/dht/find_peers.cpp
    src/librats/dht/announce.h
    src/librats/dht/announce.cpp
    src/librats/dht/storage.h
    src/librats/dht/storage.cpp
    src/librats/dht/dos_blocker.h
    src/librats/dht/dos_blocker.cpp
    src/librats/dht/node.h
    src/librats/dht/node.cpp
    src/librats/dht/udp_transport.h
    src/librats/dht/udp_transport.cpp
    src/librats/dht/dht_runner.h
    src/librats/dht/dht_runner.cpp
    src/librats/dht/persistence.h
    src/librats/dht/persistence.cpp
    src/librats/bittorrent/bencode.h
    src/librats/bittorrent/bencode.cpp

# mdns/ — local-network service discovery
    src/librats/mdns/mdns.h
    src/librats/mdns/log.h
    src/librats/mdns/mdns.cpp
    # Apple-only backend; the whole translation unit is #if'd out elsewhere, which
    # keeps this list platform-independent.
    src/librats/mdns/mdns_dnssd.h
    src/librats/mdns/mdns_dnssd.cpp

# crypto/ — hashes, ciphers, KDFs
    src/librats/crypto/sha1.h
    src/librats/crypto/sha1.cpp
    src/librats/crypto/crc32.h
    src/librats/crypto/crc32.cpp
    src/librats/crypto/curve25519.c
    src/librats/crypto/curve25519.h
    src/librats/crypto/chacha.c
    src/librats/crypto/chacha.h
    src/librats/crypto/poly1305.c
    src/librats/crypto/poly1305.h
    src/librats/crypto/chachapoly.c
    src/librats/crypto/chachapoly.h
    src/librats/crypto/sha256.c
    src/librats/crypto/sha256.h
    src/librats/crypto/sha512.c
    src/librats/crypto/sha512.h
    src/librats/crypto/hkdf.c
    src/librats/crypto/hkdf.h
    src/librats/crypto/blake2s.c
    src/librats/crypto/blake2s.h
    src/librats/crypto/blake2b.c
    src/librats/crypto/blake2b.h
    src/librats/crypto/blake2_endian.h

# crypto/ — Noise Protocol framework (Noise_XX transport encryption)
    src/librats/crypto/noise.cpp
    src/librats/crypto/noise.h

# nat/ — STUN public-IP discovery + UPnP IGD / NAT-PMP port forwarding
    src/librats/nat/stun.h
    src/librats/nat/stun.cpp
    src/librats/nat/port_mapping.h
    src/librats/nat/upnp.h
    src/librats/nat/upnp.cpp
    src/librats/nat/natpmp.h
    src/librats/nat/natpmp.cpp
)

# Add BitTorrent sources if RATS_SEARCH_FEATURES is enabled
if(RATS_SEARCH_FEATURES)
    list(APPEND LIBRARY_SOURCES
        src/librats/bittorrent/types.h
        src/librats/bittorrent/types.cpp
        src/librats/bittorrent/byte_io.h
        src/librats/bittorrent/bitfield.h
        src/librats/bittorrent/bitfield.cpp
        src/librats/bittorrent/file_storage.h
        src/librats/bittorrent/file_storage.cpp
        src/librats/bittorrent/magnet_uri.h
        src/librats/bittorrent/magnet_uri.cpp
        src/librats/bittorrent/torrent_info.h
        src/librats/bittorrent/torrent_info.cpp
        src/librats/bittorrent/store_buffer.h
        src/librats/bittorrent/store_buffer.cpp
        src/librats/bittorrent/disk_io.h
        src/librats/bittorrent/disk_io.cpp
        src/librats/bittorrent/piece_picker.h
        src/librats/bittorrent/piece_picker.cpp
        src/librats/bittorrent/reactor.h
        src/librats/bittorrent/reactor.cpp
        src/librats/bittorrent/peer_connection.h
        src/librats/bittorrent/peer_connection.cpp
        src/librats/bittorrent/choker.h
        src/librats/bittorrent/choker.cpp
        src/librats/bittorrent/torrent.h
        src/librats/bittorrent/torrent.cpp
        src/librats/bittorrent/client.h
        src/librats/bittorrent/client.cpp
        src/librats/bittorrent/extensions.h
        src/librats/bittorrent/extensions.cpp
        src/librats/bittorrent/peer_list.h
        src/librats/bittorrent/peer_list.cpp
        src/librats/bittorrent/tracker.h
        src/librats/bittorrent/tracker.cpp
        src/librats/bittorrent/resume_data.h
        src/librats/bittorrent/resume_data.cpp
        src/librats/bittorrent/torrent_creator.h
        src/librats/bittorrent/torrent_creator.cpp
        src/librats/subsystems/bittorrent.h
        src/librats/subsystems/bittorrent.cpp
    )
endif()

# Add Storage sources if RATS_STORAGE is enabled
# StorageManager is a Node subsystem (reaches the mesh via PeerNetwork).
if(RATS_STORAGE)
    list(APPEND LIBRARY_SOURCES
        src/librats/storage/storage.cpp
        src/librats/storage/storage.h
    )
endif()

if(RATS_BINDINGS)
    list(APPEND LIBRARY_SOURCES
        src/librats/bindings/rats.h
        src/librats/bindings/rats.cpp
    )
endif()

# Create library with appropriate type
if(RATS_SHARED_LIBRARY)
    add_library(rats SHARED ${LIBRARY_SOURCES})
    set_target_properties(rats PROPERTIES
        VERSION ${VERSION_STRING}
        SOVERSION ${VERSION_MAJOR}
    )
    # PRIVATE: dllexport while compiling the library itself.
    # INTERFACE: dllimport for anyone linking the shared library. This rides the
    # exported target (install(EXPORT) writes it into ratsTargets.cmake), which
    # covers find_package and vcpkg. It is belt-and-braces: the generated
    # librats/util/features.h defines RATS_IMPORT_DLL too, which is what reaches
    # consumers that never read the CMake target (vcpkg's MSBuild integration, a
    # hand-rolled -I build). Both derive from RATS_SHARED_LIBRARY and the header
    # guards with #ifndef, so they cannot disagree or redefine.
    target_compile_definitions(rats
        PRIVATE   RATS_EXPORT_DLL
        INTERFACE RATS_IMPORT_DLL
    )
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
#
# The include root is the PARENT of the librats/ directory — src/ in the build
# tree, <prefix>/include once installed — and every header spells its own path in
# full, "librats/<subdir>/<name>.h", even for a sibling in the same directory.
# That is what makes an installed header compile from -I<prefix>/include alone
# and keeps generic names (core/, node/, util/, …) off the consumer's include
# path. Do not add src/librats or include/librats as a second root: a header that
# resolved only through it would build in-tree and break for installed consumers.
target_include_directories(rats
    PUBLIC
        $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src>
        $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}/src>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
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
    target_link_libraries(rats ws2_32 iphlpapi bcrypt advapi32)
endif()

if(ANDROID)
    # The logger routes console output through __android_log_print, because an app's
    # stdout/stderr go nowhere on Android.
    find_library(log-lib log)
    target_link_libraries(rats ${log-lib})

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

# Create the main executable (the rats-client reference application)
if(RATS_BUILD_CLIENT)
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
        tests/test_dht_shutdown.cpp
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
        tests/test_transport_udp.cpp
        tests/test_relay_link.cpp
        tests/test_dialer.cpp
        tests/test_peer_table.cpp
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
        tests/test_nat_status.cpp
        tests/test_hole_punch.cpp
        tests/test_relay.cpp
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
    
    # test_mdns.cpp drives MdnsClient's own multicast socket, which Apple platforms do
    # not use (see MdnsBackend in subsystems/mdns_discovery.h), so it stays off there.
    if(NOT APPLE)
        list(APPEND TEST_SOURCES tests/test_mdns.cpp)
    else()
        list(APPEND TEST_SOURCES tests/test_mdns_dnssd.cpp)
    endif()
    # The subsystem test is backend-agnostic — it covers the adapter's lifecycle, not
    # the network — so it runs everywhere.
    list(APPEND TEST_SOURCES tests/test_mdns_discovery.cpp)
    
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

# Examples (opt-in; the BitTorrent example additionally requires RATS_SEARCH_FEATURES)
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
        INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
    )

    # Headers form a tightly coupled graph (node.h pulls in transport/core, and
    # with the search/storage features dht/krpc/bencode/bt_*/storage too), so
    # install the whole header tree. The installed layout mirrors src/librats/
    # exactly, which is what keeps "librats/<subdir>/<name>.h" resolving the same
    # in-tree and installed. .cpp / .c / .in files are excluded.
    install(DIRECTORY ${PROJECT_SOURCE_DIR}/src/librats/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/librats
        FILES_MATCHING
            PATTERN "*.h"
            PATTERN "*.hpp"
    )
    # Generated headers mirror their in-tree location (src/librats/util/<name>.h):
    # sources include them as "librats/util/<name>.h", so they must land under
    # librats/util/. features.h is what makes the installed tree self-describing —
    # without it a consumer that does not go through the exported CMake target
    # (vcpkg's MSBuild integration, a hand-rolled -I build) reads the headers with
    # RATS_SEARCH_FEATURES unset even when the library was built with it.
    install(FILES
        ${PROJECT_BINARY_DIR}/src/librats/util/version.h
        ${PROJECT_BINARY_DIR}/src/librats/util/features.h
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/librats/util
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