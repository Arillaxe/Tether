cmake_minimum_required(VERSION 3.10)
project(Tether)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Add include directories
include_directories(${OPENSSL_INCLUDE_DIR})

# Add source files
file(GLOB SOURCES "src/*.cpp")

# Create executable
add_executable(Tether ${SOURCES})

# Link OpenSSL libraries
target_link_libraries(Tether ${OPENSSL_LIBRARIES})
