cmake_minimum_required(VERSION 3.10)

# Examples can be built standalone or as part of the main project.
if(NOT TARGET rats)
    project(librats_examples)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if(NOT DEFINED LIBRATS_SOURCE_DIR)
        set(LIBRATS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
    endif()
    if(NOT DEFINED LIBRATS_BUILD_DIR)
        set(LIBRATS_BUILD_DIR "${LIBRATS_SOURCE_DIR}/build")
    endif()
    add_subdirectory(${LIBRATS_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/librats_build)
endif()

# NOTE: the previous examples (basic_p2p, peer_discovery, bt_download,
# bt_metadata_bench) were written against the old RatsClient API and were removed
# in the core redesign. The `rats-client` target (src/main.cpp) is the current
# minimal example built on the new Node API. New Node-based examples will be
# added here as the API stabilises.
