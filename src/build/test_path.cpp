#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}
std::string WideToAnsi(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

int main() {
    std::string nameInput = "ak";
    std::string keyInput = "NatsuXAK2026";
    
    // Simulating exactly what GetInput does with trimming
    while (!keyInput.empty() && (keyInput.back() == '\r' || keyInput.back() == '\n' || keyInput.back() == ' ' || keyInput.back() == '\t')) {
        keyInput.pop_back();
    }
    size_t start = 0;
    while (start < keyInput.length() && (keyInput[start] == ' ' || keyInput[start] == '\t' || keyInput[start] == '\r' || keyInput[start] == '\n')) {
        start++;
    }
    keyInput = keyInput.substr(start);

    std::wstring ADMIN_NAME = AnsiToWide(nameInput);
    std::wstring ADMIN_KEY = AnsiToWide(keyInput);
    
    std::wstring path = L"/auth?name=" + ADMIN_NAME + L"&key=" + ADMIN_KEY;
    std::cout << "PATH: '" << WideToAnsi(path) << "'\n" << std::endl;
    return 0;
}
