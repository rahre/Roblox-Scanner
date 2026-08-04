#include <iostream>
#include <string>
#include <windows.h>

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);
    return wstr;
}

int main() {
    std::string n = "ak";
    std::wstring wn = AnsiToWide(n);
    std::wstring headers = L"X-Name: " + wn + L"\r\nX-Key: test\r\n";
    std::wcout << "Length of headers: " << headers.length() << std::endl;
    std::wcout << "Headers w/ cout: " << headers << std::endl;
    std::wcout << "wcslen(headers.c_str()): " << wcslen(headers.c_str()) << std::endl;
    return 0;
}
