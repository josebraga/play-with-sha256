#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include <openssl/sha.h>

std::string sha256(const std::string str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }

    return ss.str();
}

int main()
{
    std::cout << sha256("1234567890_1") << '\n';
    std::cout << sha256("1234567890_2") << '\n';
    std::cout << sha256("1234567890_3") << '\n';
    std::cout << sha256("1234567890_4") << '\n';
    std::cout << sha256("zfeDBQcVZ26gYFVu6U3xRuR+dHcDvHwg9MmkaOMHDs6TSibyY5LnfrRxFzktGyq/4DzpS/"
                        "gwub4wqOOet5m7eQ==")
              << '\n';

    // is "5f47e5ae89e2fc953432481140e1c8d44106c9abdd8ce5cddd66f728b914dbf7" ?
}
