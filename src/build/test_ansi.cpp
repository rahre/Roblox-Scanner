#include <iostream>
#include <string>
#include <windows.h>

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_ACP, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

int main() {
    std::string test = "NatsuXAK2026";
    std::wstring wide = AnsiToWide(test);
    std::wcout << L"wide length: " << wide.length() << std::endl;
    std::wcout << L"wide: '" << wide << L"'" << std::endl;
    if (wide == L"NatsuXAK2026") {
        std::wcout << L"EQUAL" << std::endl;
    } else {
        std::wcout << L"NOT EQUAL" << std::endl;
    }
    return 0;
}
