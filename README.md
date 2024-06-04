# OpenSSL-EVP Helper

OpenSSL-EVP Helper is a C++ library that makes it easier to work with EVP in the [OpenSSL](https://github.com/openssl/openssl) library.

## Installation

Use [CMake](https://cmake.org/) and module [FetchContent](https://cmake.org/cmake/help/latest/module/FetchContent.html) to install OpenSSL-EVP Helper.

```cmake
include(FetchContent)

FetchContent_Declare(
    openssl-evp
    GIT_REPOSITORY https://github.com/Sanya056756/openssl-evp.git
    GIT_TAG master
)

FetchContent_MakeAvailable(openssl_evp)

...

target_link_libraries(target_name PRIVATE OpenSSL::EVP_Helper)
```

## Usage

```cpp
#include <iostream>

#include <hash/hash.h>

class MD5 : public Hash
{
    MD5() : Hash("md5") {}
};

int main()
{
    MD5 md5;

    if (!md5.init())
        throw std::runtime_error("Failed to init MD5");

    if (!md5.update("Hello World!")) // Input string
        throw std::runtime_error("Failed to update MD5");

    if (!md5.final())
        throw std::runtime_error("Failed to final MD5");

    std::cout << "Final hex string is " << md5.hex() << std::endl;
}
```

## Contributing

I'm always open to discussing any suggestions for improving the project.
