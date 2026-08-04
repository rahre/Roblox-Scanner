#include <iostream>
#include <string>

int main() {
    std::string body = "{\"error\": \"Forbidden\"}";
    size_t rpos = body.find("\"role\"");
    if (rpos != std::string::npos) {
        std::cout << "Found role" << std::endl;
    } else {
        std::cout << "Role not found" << std::endl;
    }
    return 0;
}
