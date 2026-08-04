#include <iostream>
#include <string>
#include <fstream>

int main() {
    std::ofstream outCfg(".admin_config", std::ios::binary);
    outCfg << "ak\r\n";
    outCfg << "NatsuXAK2026\r\n";
    outCfg.close();

    std::string nameInput, keyInput;
    std::ifstream cfg(".admin_config");
    if (cfg.is_open()) {
        std::getline(cfg, nameInput);
        std::getline(cfg, keyInput);
        cfg.close();
        
        auto trim = [](std::string& s) {
            while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
        };
        trim(nameInput);
        trim(keyInput);
    }
    
    std::cout << "Name: '" << nameInput << "'\n";
    std::cout << "Key: '" << keyInput << "'\n";
    std::cout << "Name length: " << nameInput.length() << "\n";
    std::cout << "Key length: " << keyInput.length() << "\n";
    return 0;
}
