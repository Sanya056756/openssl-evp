#include <hash/hash.h>

#include <iomanip>
#include <cstring>
#include <sstream>

Hash::Hash(const char* digest_by_name) :
    m_md(EVP_get_digestbyname(digest_by_name)), m_ctx(EVP_MD_CTX_new()) {}

Hash::~Hash()
{
    EVP_MD_CTX_free(m_ctx);
}

bool Hash::init() const
{
    return EVP_DigestInit(m_ctx, m_md);
}

bool Hash::update(const char* text) const
{
    return EVP_DigestUpdate(m_ctx, text, strlen(text));
}

bool Hash::final()
{
    return EVP_DigestFinal(m_ctx, m_md_values, &m_md_len);
}

const unsigned char* Hash::get_md_values() const
{
    return m_md_values;
}

unsigned int Hash::size() const
{
    return m_md_len;
}

std::string Hash::hex() const
{
    std::stringstream ss;
    for (int i = 0; i < m_md_len; ++i)
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)m_md_values[i];

    return ss.str();
}