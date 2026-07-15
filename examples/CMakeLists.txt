cmake_minimum_required(VERSION 3.14)

# librats usage examples.
#
# These are compiled only when the main project is configured with
# -DRATS_BUILD_EXAMPLES=ON (OFF by default; CI turns it on). They can also be
# built standalone against a source checkout of librats:
#
#   cmake -S examples -B build-examples
#   cmake --build build-examples
#
# Each .cpp below becomes one executable named after its file (without the
# leading NN_ index), linked against the rats library.

# Standalone build: pull in the library from the parent directory when the rats
# target has not already been defined by the top-level project.
if(NOT TARGET rats)
    project(librats_examples CXX)
    set(CMAKE_CXX_STANDARD 17)
    set(CMAKE_CXX_STANDARD_REQUIRED ON)

    if(NOT DEFINED LIBRATS_SOURCE_DIR)
        set(LIBRATS_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/..")
    endif()
    # Don't rebuild the library's own tests/client/examples just to get libs.
    set(RATS_BUILD_TESTS    OFF CACHE BOOL "" FORCE)
    set(RATS_BUILD_CLIENT   OFF CACHE BOOL "" FORCE)
    set(RATS_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
    add_subdirectory(${LIBRATS_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/librats_build)
endif()

# Examples that only need the core Node + always-available subsystems.
set(RATS_EXAMPLES
    01_chat.cpp
    02_pubsub.cpp
    03_typed_messaging.cpp
    04_file_transfer.cpp
    05_dht_discovery.cpp
    07_full_chat.cpp
)

# Examples that require the BitTorrent subsystem (RATS_SEARCH_FEATURES).
if(RATS_SEARCH_FEATURES)
    list(APPEND RATS_EXAMPLES
        06_bittorrent_download.cpp
    )
endif()

foreach(example_src IN LISTS RATS_EXAMPLES)
    # Target name = file name without the "NN_" ordering prefix or extension:
    #   01_chat.cpp -> chat
    get_filename_component(example_name "${example_src}" NAME_WE)
    string(REGEX REPLACE "^[0-9]+_" "" example_name "${example_name}")

    add_executable(${example_name} "${example_src}")
    target_link_libraries(${example_name} PRIVATE rats)
    set_target_properties(${example_name} PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}/bin/examples
    )
endforeach()
