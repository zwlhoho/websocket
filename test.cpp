#include <sstream>
#include <iostream>
#include <cstring>
#include <vector>

#include "base64.h"
#include <openssl/sha.h>
void sha1_generation(const char *str, char *sha1_str) {
    unsigned char digest[SHA_DIGEST_LENGTH + 1] = {0};
    SHA1((const unsigned char *)str, strlen(str), (unsigned char *)digest);
    for(int index = 0; index < SHA_DIGEST_LENGTH; ++index) {
        sprintf(&sha1_str[index*2], "%02x", (unsigned int)digest[index]);
    }
    printf("str: %s\nsha1_str: %s\ndigest: %s\n", str, sha1_str, digest);
}

int main(int argc, char const *argv[])
{
    const char *pread_data = "GET /my-echo-protocol HTTP/1.1\r\nHost: 192.168.43.101:18081\r\nConnection: Upgrade\r\nPragma: no-cache\r\nCache-Control: no-cache\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36\r\nUpgrade: websocket\r\nOrigin: file://\r\nSec-WebSocket-Version: 13\r\nAccept-Encoding: gzip, deflate\r\nAccept-Language: zh-CN,zh;q=0.9\r\nSec-WebSocket-Key: GdNPRUqcXm8u4tUsdixsxA==\r\nSec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n";
    std::string read_data_str(pread_data);
    std::vector<std::string> lines;
    std::size_t startIndex = 0;
    std::size_t spiltIndex = std::string::npos;
    
    while (std::string::npos != (spiltIndex = read_data_str.find("\r\n", startIndex))) {
        std::string substr(read_data_str.substr(startIndex, spiltIndex - startIndex ));
        std::cout << substr << std::endl ;
        lines.push_back(substr);
        startIndex = spiltIndex + strlen("\r\n");
    }

    char sha1_str[SHA_DIGEST_LENGTH * 2 + 1];
    sha1_generation("Hello sha1!", sha1_str);

    Base64 base64;
    std::string base64Str = base64.Encode((const unsigned char *)"dafddXCAD8329e&OOOII&^TYI**(IIIIOUY你好", strlen("dafddXCAD8329e&OOOII&^TYI**(IIIIOUY你好"));
    std::cout << base64Str << std::endl;

    return 0;
}
