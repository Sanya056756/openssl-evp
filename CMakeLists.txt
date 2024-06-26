cmake_minimum_required(VERSION 3.28)
project(hash DESCRIPTION "EVP helper for OpenSSL")

set(CMAKE_CXX_STANDARD 11)

find_package(OpenSSL REQUIRED)

if (BUILD_SHARED_LIBS)
    add_library(${PROJECT_NAME} SHARED src/hash.cpp)
else ()
    add_library(${PROJECT_NAME} STATIC src/hash.cpp)
endif ()

target_include_directories(${PROJECT_NAME} PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include INTERFACE ${OPENSSL_INCLUDE_DIR})

target_link_options(${PROJECT_NAME} PRIVATE -L${OPENSSL_SSL_LIBRARY} -L${OPENSSL_CRYPTO_LIBRARY})
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)

add_library(OpenSSL::EVP_Helper ALIAS ${PROJECT_NAME})