#ifndef OPENSSL_HASH_H
#define OPENSSL_HASH_H

#include <string>

#include <openssl/evp.h>

class Hash
{
public:
    explicit Hash(const char*);
    ~Hash();

    bool init() const;
    bool update(const char*) const;
    bool final();

    const unsigned char* get_md_values() const;
    unsigned int size() const;
    std::string hex() const;
private:
    const EVP_MD* m_md;
    EVP_MD_CTX* m_ctx;

    unsigned char m_md_values[EVP_MAX_MD_SIZE]{};
    unsigned int m_md_len{};
};

#endif //OPENSSL_HASH_H