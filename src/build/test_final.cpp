#include <iostream>
#include <string>
#include <fstream>
#include <windows.h>
#include <winhttp.h>

std::wstring AnsiToWide(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, nullptr, 0);
    std::wstring wstr(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, &wstr[0], size);
    
    // THE BUG IS HERE. MultiByteToWideChar includes the null terminator if you pass -1.
    // The wstring now has an embedded null character.
    // Let's strip it!
    if (!wstr.empty() && wstr.back() == L'\0') {
        wstr.pop_back();
    }
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
    
    std::wstring headers = L"X-Name: " + ADMIN_NAME + L"\r\nX-Key: " + ADMIN_KEY + L"\r\nContent-Type: application/json\r\n";
    
    std::cout << "HEADER LEN: " << headers.length() << std::endl;
    std::cout << "WCSLEN: " << wcslen(headers.c_str()) << std::endl;
    
    std::wstring url = L"roblox-scanner-hioo.onrender.com";
    std::wstring path = L"/checker/add";
    
    HINTERNET hSession = WinHttpOpen(L"NatsuXAK Admin/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, url.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    std::string cname = "rico5";
    std::string body = "{\"name\":\"" + cname + "\",\"key\":\"PENDING\",\"role\":\"checker\",\"master_key\":\"" + WideToAnsi(ADMIN_KEY) + "\"}";

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)body.c_str(), body.length(), body.length(), 0);
    if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);
    
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (bResults) WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    
    std::cout << "Status: " << statusCode << std::endl;
    return 0;
}
