#include <iostream>
#include <string>

std::string UrlEncode(const std::string& value) {
    std::string escaped;
    for (char c : value) {
        if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            escaped += c;
        } else {
            char buf[10];
            sprintf(buf, "%%%02X", (unsigned char)c);
            escaped += buf;
        }
    }
    return escaped;
}

int main() {
    std::string nameInput = "ak";
    std::string keyInput = "NatsuXAK2026";
    
    std::string path = "/auth?name=" + UrlEncode(nameInput) + "&key=" + UrlEncode(keyInput);
    std::cout << "PATH: '" << path << "'\n" << std::endl;
    return 0;
}
