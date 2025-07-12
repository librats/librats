cmake_minimum_required(VERSION 3.10)
project(librats VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Create the library
add_library(librats
    src/network.cpp
    src/network.h
    src/udp_network.cpp
    src/udp_network.h
    src/network_utils.cpp
    src/network_utils.h
    src/dht.cpp
    src/dht.h
    src/bencode.cpp
    src/bencode.h
    src/krpc.cpp
    src/krpc.h
    src/librats.cpp
    src/librats.h
    src/logger.h
)

# Include directories
target_include_directories(librats PUBLIC src)

# Find and link threading support
find_package(Threads REQUIRED)
target_link_libraries(librats Threads::Threads)

# Link networking libraries
if(WIN32)
    target_link_libraries(librats ws2_32)
endif()

# Create the main executable
add_executable(rats src/main.cpp)
target_link_libraries(rats librats)

# Set output directories
set_target_properties(librats PROPERTIES
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
)

set_target_properties(rats PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)
