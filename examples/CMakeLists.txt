cmake_minimum_required(VERSION 3.10)

# Examples can be built standalone or as part of the main project
if(NOT TARGET rats)
    project(librats_examples)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)
    
    # When building standalone, find the library
    # Adjust the path to where librats was built
    if(NOT DEFINED LIBRATS_SOURCE_DIR)
        set(LIBRATS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
    endif()
    
    if(NOT DEFINED LIBRATS_BUILD_DIR)
        set(LIBRATS_BUILD_DIR "${LIBRATS_SOURCE_DIR}/build")
    endif()
    
    # Add the main library as a subdirectory
    add_subdirectory(${LIBRATS_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/librats_build)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# Basic examples (no optional features required)
# ─────────────────────────────────────────────────────────────────────────────

# Example: Basic P2P messaging
# Demonstrates connections, string/JSON messaging, and the on/send API
# Usage: basic_p2p <listen_port> [<remote_ip> <remote_port>]
add_executable(basic_p2p basic_p2p.cpp)
target_link_libraries(basic_p2p rats)
set_target_properties(basic_p2p PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
)

# Example: Peer discovery (DHT + mDNS)
# Demonstrates DHT and mDNS discovery, custom protocol, periodic stats
# Usage: peer_discovery <listen_port> [<protocol_name>]
add_executable(peer_discovery peer_discovery.cpp)
target_link_libraries(peer_discovery rats)
set_target_properties(peer_discovery PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
)

# ─────────────────────────────────────────────────────────────────────────────
# BitTorrent examples (require RATS_SEARCH_FEATURES)
# ─────────────────────────────────────────────────────────────────────────────
if(RATS_SEARCH_FEATURES)
    # Metadata fetch benchmark
    # Fetches torrent metadata from a specific peer and measures the time
    # Usage: bt_metadata_bench <ip> <port> <info_hash_hex>
    add_executable(bt_metadata_bench bt_metadata_bench.cpp)
    target_link_libraries(bt_metadata_bench rats)
    set_target_properties(bt_metadata_bench PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    )

    # Torrent download
    # Downloads a torrent (by info hash from a peer) to a specified directory
    # Usage: bt_download <ip> <port> <info_hash_hex> <download_dir>
    add_executable(bt_download bt_download.cpp)
    target_link_libraries(bt_download rats)
    set_target_properties(bt_download PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/bin
    )
endif()
