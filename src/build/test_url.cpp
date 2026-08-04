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

std::wstring UrlEncode(const std::wstring& value) {
    std::wstring escaped;
    for (wchar_t c : value) {
        if (iswalnum(c) || c == L'-' || c == L'_' || c == L'.' || c == L'~') {
            escaped += c;
        } else {
            wchar_t buf[10];
            swprintf(buf, 10, L"%%%02X", (unsigned int)c);
            escaped += buf;
        }
    }
    return escaped;
}

int main() {
    std::string nameInput = "ak";
    std::string keyInput = "NatsuXAK2026";
    
    // Simulate what the C++ code receives
    std::wstring ADMIN_NAME = AnsiToWide(nameInput);
    std::wstring ADMIN_KEY = AnsiToWide(keyInput);
    
    std::wstring path = L"/auth?name=" + UrlEncode(ADMIN_NAME) + L"&key=" + UrlEncode(ADMIN_KEY);
    std::cout << "ENCODED PATH: '" << WideToAnsi(path) << "'\n" << std::endl;
    return 0;
}
