#include <hash/hash.h> // header

#include <iomanip>
#include <cstring>
#include <sstream>

Hash::Hash(const char* digest_by_name) :
    md(EVP_get_digestbyname(digest_by_name)), ctx(EVP_MD_CTX_new()) {}

Hash::~Hash()
{
    EVP_MD_CTX_free(ctx);
}

bool Hash::init() const
{
    return EVP_DigestInit(ctx, md);
}

bool Hash::update(const char* text) const
{
    return EVP_DigestUpdate(ctx, text, strlen(text));
}

bool Hash::final()
{
    return EVP_DigestFinal(ctx, md_value, &md_len);
}

const unsigned char* Hash::get_md_values() const
{
    return md_value;
}

unsigned int Hash::size() const
{
    return md_len;
}

std::string Hash::hex() const
{
    std::stringstream ss;
    for (int i = 0; i < md_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)md_value[i];

    return ss.str();
}