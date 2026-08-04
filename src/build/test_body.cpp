#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);
    return wstr;
}

std::string WideToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string str(size, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), -1, &str[0], size, nullptr, nullptr);
    if (!str.empty() && str.back() == '\0') str.pop_back();
    return str;
}

int main() {
    std::ofstream outCfg(".admin_config", std::ios::binary);
    outCfg << "ak\r\nNatsuXAK2026\r\n";
    outCfg.close();

    std::string nameInput, keyInput;
    std::ifstream cfg(".admin_config");
    std::getline(cfg, nameInput);
    std::getline(cfg, keyInput);
    cfg.close();
    
    auto trim = [](std::string& s) {
        while (!s.empty() && (s.back() == '\r' || s.back() == '\n' || s.back() == ' ' || s.back() == '\t')) s.pop_back();
    };
    trim(nameInput);
    trim(keyInput);
    
    std::wstring ADMIN_NAME = AnsiToWide(nameInput);
    std::wstring ADMIN_KEY = AnsiToWide(keyInput);
    std::string cname = "rico5";
    
    std::string body = "{\"name\":\"" + cname + "\",\"key\":\"PENDING\",\"role\":\"checker\",\"master_key\":\"" + WideToAnsi(ADMIN_KEY) + "\"}";
    
    std::cout << "BODY: " << body << std::endl;
    std::cout << "BODY LENGTH: " << body.length() << std::endl;
    for(char c : body) {
        std::cout << (int)c << " ";
    }
    std::cout << std::endl;
    return 0;
}
