cmake_minimum_required(VERSION 3.28)
project(hash)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -I%OPENSSL_ROOT_DIR%/include -L%OPENSSL_ROOT_DIR%/lib")

find_package(OpenSSL REQUIRED)

include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include ${OPENSSL_INCLUDE_DIR})

# hash
add_library(${PROJECT_NAME} SHARED src/hash.cpp)
target_link_directories(${PROJECT_NAME} INTERFACE ${OPENSSL_LIBRARIES})
target_link_libraries(${PROJECT_NAME} ssl crypto)