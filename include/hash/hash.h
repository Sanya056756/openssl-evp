#ifndef OPENSSL_HASH_H
#define OPENSSL_HASH_H

#include <openssl/evp.h>
#include <string>

class Hash
{
public:
    Hash(const char*);
    ~Hash();

    bool init() const;
    bool update(const char*) const;
    bool final();

    const unsigned char* get_md_values() const;
    unsigned int size() const;
    std::string hex() const;
private:
    const EVP_MD* md;
    EVP_MD_CTX* ctx;

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
};

#endif //OPENSSL_HASH_H