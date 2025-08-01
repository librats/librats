cmake_minimum_required(VERSION 3.10)
project(librats VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create the library
add_library(rats
    src/socket.cpp
    src/socket.h
    src/network_utils.cpp
    src/network_utils.h
    src/dht.cpp
    src/dht.h
    src/bencode.cpp
    src/bencode.h
    src/bittorrent.cpp
    src/bittorrent.h
    src/krpc.cpp
    src/krpc.h
    src/librats.cpp
    src/librats.h
    src/sha1.cpp
    src/sha1.h
    src/os.cpp
    src/os.h
    src/stun.cpp
    src/stun.h
    src/ice.cpp
    src/ice.h
    src/fs.cpp
    src/fs.h
    src/logger.h
    src/noise.cpp
    src/noise.h
    src/encrypted_socket.cpp
    src/encrypted_socket.h
    src/mdns.cpp
    src/mdns.h
    src/threadmanager.cpp
    src/threadmanager.h
)

# Include directories
target_include_directories(rats PUBLIC src)

# Find and link threading support
find_package(Threads REQUIRED)
target_link_libraries(rats Threads::Threads)

# Link networking libraries
if(WIN32)
    target_link_libraries(rats ws2_32 iphlpapi bcrypt)
endif()

# Create the main executable
add_executable(rats-client src/main.cpp)
target_link_libraries(rats-client rats)

# Set output directories
set_target_properties(rats PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

set_target_properties(rats-client PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

# Testing setup
option(BUILD_TESTS "Build unit tests" ON)

if(BUILD_TESTS)
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
    
    # Create test executable
    add_executable(librats_tests
        tests/test_socket.cpp
        tests/test_bencode.cpp
        tests/test_sha1.cpp
        tests/test_network_utils.cpp
        tests/test_dht.cpp
        tests/test_rats_client.cpp
        tests/test_os.cpp
        tests/test_stun.cpp
        tests/test_ice.cpp
        tests/test_fs.cpp
        tests/test_config_persistence.cpp
        tests/test_main.cpp
        tests/test_message_exchange.cpp
        tests/test_noise.cpp
        tests/test_mdns.cpp
    )
    
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
    gtest_discover_tests(librats_tests)
    
    # Set test output directory
    set_target_properties(librats_tests PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    )
endif()
