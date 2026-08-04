#include <iostream>
#include <string>

int main() {
    std::string resp_body = "{\n  \"role\": \"master\"\n}";
    size_t rpos = resp_body.find("\"role\"");
    std::cout << "Body: '" << resp_body << "'\n";
    std::cout << "rpos: " << (int)rpos << std::endl;
    std::string ROLE;
    if (rpos != std::string::npos) {
        size_t colon_pos = resp_body.find(':', rpos);
        std::cout << "colon_pos: " << (int)colon_pos << std::endl;
        if (colon_pos != std::string::npos) {
            size_t q1 = resp_body.find('"', colon_pos);
            std::cout << "q1: " << (int)q1 << std::endl;
            if (q1 != std::string::npos) {
                size_t q2 = resp_body.find('"', q1 + 1);
                std::cout << "q2: " << (int)q2 << std::endl;
                if (q2 != std::string::npos) {
                    ROLE = resp_body.substr(q1 + 1, q2 - q1 - 1);
                    std::cout << "ROLE='" << ROLE << "'" << std::endl;
                }
            }
        }
    }
    return 0;
}
