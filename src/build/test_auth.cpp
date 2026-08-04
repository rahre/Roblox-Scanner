#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>

const std::wstring RENDER_URL = L"roblox-scanner-hioo.onrender.com";
const INTERNET_PORT RENDER_PORT = INTERNET_DEFAULT_HTTPS_PORT;
std::wstring ADMIN_NAME = L"ak";
std::wstring ADMIN_KEY = L"NatsuXAK2026";

struct ServerResponse {
    bool success;
    int status;
    std::string body;
};

ServerResponse HttpRequest(const std::wstring& method, const std::wstring& path, 
                           const std::string& postBody = "", 
                           const std::vector<std::pair<std::wstring, std::wstring>>& customHeaders = {}) {
    
    ServerResponse result = {false, 0, ""};
    
    HINTERNET hSession = WinHttpOpen(L"NatsuXAK Admin/5.0",
                                     WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                     WINHTTP_NO_PROXY_NAME,
                                     WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return result;

    HINTERNET hConnect = WinHttpConnect(hSession, RENDER_URL.c_str(), RENDER_PORT, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
                                                NULL, WINHTTP_NO_REFERER,
                                                WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                WINHTTP_FLAG_SECURE);
        if (hRequest) {
            std::wstring headers = L"X-Name: " + ADMIN_NAME + L"\r\nX-Key: " + ADMIN_KEY + L"\r\n";
            for (const auto& h : customHeaders) {
                headers += h.first + L": " + h.second + L"\r\n";
            }
            if (!postBody.empty()) {
                headers += L"Content-Type: application/json\r\n";
            }

            BOOL bResults = WinHttpSendRequest(hRequest, headers.c_str(), -1,
                                               (LPVOID)postBody.c_str(), postBody.length(),
                                               postBody.length(), 0);

            if (bResults) {
                bResults = WinHttpReceiveResponse(hRequest, NULL);
            } else {
                 std::cout << "WinHttpSendRequest failed. Error: " << GetLastError() << std::endl;
            }

            if (bResults) {
                DWORD statusCode = 0;
                DWORD size = sizeof(statusCode);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &size, WINHTTP_NO_HEADER_INDEX);
                result.status = statusCode;

                DWORD dwSize = 0;
                DWORD dwDownloaded = 0;
                do {
                    dwSize = 0;
                    if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) break;
                    if (dwSize == 0) break;
                    char* pszOutBuffer = new char[dwSize + 1];
                    if (WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                        pszOutBuffer[dwDownloaded] = '\0';
                        result.body += pszOutBuffer;
                    }
                    delete[] pszOutBuffer;
                } while (dwSize > 0);
                
                result.success = (statusCode == 200);
            } else {
                 std::cout << "WinHttpReceiveResponse failed. Error: " << GetLastError() << std::endl;
            }
            WinHttpCloseHandle(hRequest);
        } else {
             std::cout << "WinHttpOpenRequest failed. Error: " << GetLastError() << std::endl;
        }
        WinHttpCloseHandle(hConnect);
    } else {
         std::cout << "WinHttpConnect failed. Error: " << GetLastError() << std::endl;
    }
    WinHttpCloseHandle(hSession);
    return result;
}

int main() {
    std::wstring path = L"/auth?name=" + ADMIN_NAME + L"&key=" + ADMIN_KEY;
    auto resp = HttpRequest(L"GET", path);
    std::cout << "Status: " << resp.status << std::endl;
    std::cout << "Success: " << resp.success << std::endl;
    std::cout << "Body: '" << resp.body << "'\n" << std::endl;

    // test json parsing exactly as written in admin.cpp
    std::cout << "Testing JSON parser..." << std::endl;
    std::string ROLE;
    size_t rpos = resp.body.find("\"role\"");
    std::cout << "rpos: " << (rpos == std::string::npos ? -1 : (int)rpos) << std::endl;
    if (rpos != std::string::npos) {
        size_t colon_pos = resp.body.find(':', rpos);
        std::cout << "colon_pos: " << (colon_pos == std::string::npos ? -1 : (int)colon_pos) << std::endl;
        if (colon_pos != std::string::npos) {
            size_t q1 = resp.body.find('"', colon_pos);
            std::cout << "q1: " << (q1 == std::string::npos ? -1 : (int)q1) << std::endl;
            if (q1 != std::string::npos) {
                size_t q2 = resp.body.find('"', q1 + 1);
                std::cout << "q2: " << (q2 == std::string::npos ? -1 : (int)q2) << std::endl;
                if (q2 != std::string::npos) {
                    ROLE = resp.body.substr(q1 + 1, q2 - q1 - 1);
                    std::cout << "PARSED ROLE: '" << ROLE << "'\n" << std::endl;
                }
            }
        }
    }

    return 0;
}
