#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>

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
    std::wstring url = L"roblox-scanner-hioo.onrender.com";
    std::wstring path = L"/checker/add";
    
    HINTERNET hSession = WinHttpOpen(L"NatsuXAK Admin/5.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = WinHttpConnect(hSession, url.c_str(), INTERNET_DEFAULT_HTTPS_PORT, 0);
    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", path.c_str(), NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
    
    std::string ADMIN_KEY = "NatsuXAK2026";
    std::string ADMIN_NAME = "ak";
    std::wstring w_name = AnsiToWide(ADMIN_NAME);
    std::wstring w_key = AnsiToWide(ADMIN_KEY);

    std::wstring headers = L"X-Name: " + w_name + L"\r\nX-Key: " + w_key + L"\r\nContent-Type: application/json\r\n";
    std::string cname = "Rico";
    std::string body = "{\"name\":\"" + cname + "\",\"key\":\"PENDING\",\"role\":\"checker\",\"master_key\":\"" + WideToAnsi(w_key) + "\"}";

    BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1, (LPVOID)body.c_str(), body.length(), body.length(), 0);
    if (bResults) bResults = WinHttpReceiveResponse(hRequest, NULL);
    
    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);
    if (bResults) WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
    
    std::cout << "Status: " << statusCode << std::endl;
    
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    std::string result_body;
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
        if (dwSize == 0) break;
        char* pszOutBuffer = new char[dwSize + 1];
        if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
            pszOutBuffer[dwDownloaded] = '\0';
            result_body += pszOutBuffer;
        }
        delete[] pszOutBuffer;
    } while (dwSize > 0);
    
    std::cout << "Body: " << result_body << std::endl;
    return 0;
}
