#include <iostream>
#include <string>

int main() {
    std::string resp_body = "{\"role\":\"master\"}"; // Testing NO spaces
    size_t rpos = resp_body.find("\"role\"");
    std::string ROLE;
    if (rpos != std::string::npos) {
        size_t colon_pos = resp_body.find(':', rpos);
        if (colon_pos != std::string::npos) {
            size_t q1 = resp_body.find('"', colon_pos); // Wait, if there are NO spaces, colon_pos is the colon. the next quote is AFTER the colon. But what if we find the NEXT quote?
            // "role":"master"
            // colon is at index 6. The next quote is at index 7. 
            // find('"', colon_pos) will find the quote at index 7? No! It will find the quote inside "role"! Wait.
            std::cout << "colon_pos: " << colon_pos << std::endl;
            size_t q1_test = resp_body.find('"', colon_pos);
            std::cout << "q1_test: " << q1_test << std::endl;
            // The colon is AT 6. find('"', 6) starts searching from 6. So it finds the first quote AFTER or AT 6.
        }
    }
    return 0;
}
