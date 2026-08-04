#include <iostream>
#include <string>

int main() {
    std::string resp_body = "{\"role\":\"master\"}"; // Testing NO spaces
    size_t rpos = resp_body.find("\"role\"");
    std::string ROLE;
    if (rpos != std::string::npos) {
        size_t colon_pos = resp_body.find(':', rpos);
        if (colon_pos != std::string::npos) {
            size_t q1 = resp.body.find('"', colon_pos);
            if (q1 != std::string::npos) {
                size_t q2 = resp.body.find('"', q1 + 1);
                if (q2 != std::string::npos) {
                    ROLE = resp_body.substr(q1 + 1, q2 - q1 - 1);
                    std::cout << "ROLE='" << ROLE << "'" << std::endl;
                }
            }
        }
    }
    return 0;
}
