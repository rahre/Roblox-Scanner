#include <iostream>
#include <string>

int main() {
    std::string body = "{\"role\": \"master\"}";
    size_t rpos = body.find("\"role\"");
    if (rpos != std::string::npos) {
        size_t colon_pos = body.find(':', rpos);
        if (colon_pos != std::string::npos) {
            size_t q1 = body.find('"', colon_pos);
            if (q1 != std::string::npos) {
                size_t q2 = body.find('"', q1 + 1);
                if (q2 != std::string::npos) {
                    std::string ROLE = body.substr(q1 + 1, q2 - q1 - 1);
                    std::cout << "ROLE: '" << ROLE << "'" << std::endl;
                }
            }
        }
    }
    return 0;
}
