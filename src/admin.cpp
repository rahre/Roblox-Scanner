#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include "ui.h"

// Constants
const std::wstring RENDER_URL = L"roblox-scanner-hioo.onrender.com";
const INTERNET_PORT RENDER_PORT = INTERNET_DEFAULT_HTTPS_PORT;
std::wstring ADMIN_NAME;
std::wstring ADMIN_KEY;
std::string ROLE;

// Utility for strings
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
    return str;
}

// Http Request Utility
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
            // Add base auth headers
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
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
    return result;
}

// Authentication
bool Authenticate() {
    ui::PrintInfo("Authenticating...");
    std::wstring path = L"/auth?name=" + ADMIN_NAME + L"&key=" + ADMIN_KEY;
    
    for (int i = 0; i < 5; ++i) {
        auto resp = HttpRequest(L"GET", path);
        if (resp.success) {
            // basic json parse
            size_t rpos = resp.body.find("\"role\"");
            if (rpos != std::string::npos) {
                size_t q1 = resp.body.find('"', rpos + 6);
                size_t q2 = resp.body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) {
                    ROLE = resp.body.substr(q1 + 1, q2 - q1 - 1);
                    return true;
                }
            }
        } else if (resp.status == 403) {
            // Explicitly rejected
            return false;
        }
        ui::PrintInfo("Retrying...");
        Sleep(3000);
    }
    return false;
}

// Menus
void AddPlayer() {
    system("cls");
    ui::PrintHeader("ADD PLAYER");
    ui::PrintInfo("One-time use -- scanner auto-deletes after scan.");
    std::string name = ui::GetInput("Player name: ");
    if (name.empty()) return;

    std::string body = "{\"auth_name\":\"" + WideToAnsi(ADMIN_NAME) + "\",\"auth_key\":\"" + WideToAnsi(ADMIN_KEY) + "\",\"player_name\":\"" + name + "\"}";
    auto resp = HttpRequest(L"POST", L"/player/add", body);
    
    if (resp.success) {
        ui::PrintSuccess("Added: " + name);
        ui::PrintInfo("When they run the scanner, it scans and self-deletes.");
        ui::PrintInfo("Report posts back to the server automatically.");
    } else {
        ui::PrintError("Error adding player.");
    }
    system("pause >nul");
}

void ViewReports() {
    system("cls");
    ui::PrintHeader("SCAN REPORTS");
    
    ui::SpinnerWait(1000, "Fetching reports...");
    auto resp = HttpRequest(L"GET", L"/reports");
    
    if (resp.success) {
        std::vector<std::string> reports;
        size_t pos = 0;
        while ((pos = resp.body.find('"', pos)) != std::string::npos) {
            pos++;
            size_t end = resp.body.find('"', pos);
            if (end == std::string::npos) break;
            reports.push_back(resp.body.substr(pos, end - pos));
            pos = end + 1;
        }

        if (reports.empty()) {
            ui::PrintInfo("No reports yet.");
        } else {
            for (size_t i = 0; i < reports.size(); ++i) {
                std::cout << ui::GOLD << "    " << (i+1) << ". " << ui::RESET << reports[i] << "\n";
            }
        }
    } else {
        ui::PrintError("Error fetching reports.");
    }

    std::cout << "\n";
    std::string rname = ui::GetInput("Enter report name to view (or 'back'): ");
    if (rname == "back" || rname.empty()) return;

    ui::SpinnerWait(500, "Downloading...");
    auto rresp = HttpRequest(L"GET", L"/report/" + AnsiToWide(rname));
    
    if (rresp.success) {
        std::cout << "\n    " << ui::DARK_GOLD << std::string(36, '=') << "\n";
        std::cout << ui::RESET << rresp.body << "\n";
        std::cout << "    " << ui::DARK_GOLD << std::string(36, '=') << "\n";
    } else {
        ui::PrintError("Report not found or access denied.");
    }
    system("pause >nul");
}

void AddChecker() {
    system("cls");
    ui::PrintHeader("ADD CHECKER");
    std::string cname = ui::GetInput("Name: ");
    if (cname.empty()) return;

    std::string body = "{\"name\":\"" + cname + "\",\"key\":\"PENDING\",\"role\":\"checker\",\"master_key\":\"" + WideToAnsi(ADMIN_KEY) + "\"}";
    auto resp = HttpRequest(L"POST", L"/checker/add", body);
    
    if (resp.success) {
        ui::PrintSuccess("Added checker: " + cname);
        ui::PrintInfo("Note: When they first launch the Service, it will permanently lock to their PC.");
        ui::PrintInfo("Give them: NatsuXAK Service.exe + scanner.exe");
    } else {
        ui::PrintError("Failed to add checker.");
    }
    system("pause >nul");
}

void RemoveChecker() {
    system("cls");
    ui::PrintHeader("REMOVE CHECKER");
    std::string cname = ui::GetInput("Checker name: ");
    if (cname.empty()) return;

    auto resp = HttpRequest(L"DELETE", L"/checker/" + AnsiToWide(cname));
    if (resp.status == 200 || resp.status == 204) {
        ui::PrintSuccess("Removed: " + cname + " (if existed)");
    } else {
        ui::PrintError("Failed to remove checker.");
    }
    system("pause >nul");
}

void ListCheckers() {
    system("cls");
    ui::PrintHeader("LIST CHECKERS");
    
    ui::SpinnerWait(1000, "Fetching checkers...");
    auto resp = HttpRequest(L"GET", L"/checkers");
    
    if (resp.success) {
        size_t pos = 0;
        bool found = false;
        while ((pos = resp.body.find('"', pos)) != std::string::npos) {
            pos++;
            size_t end = resp.body.find('"', pos);
            if (end == std::string::npos) break;
            std::cout << ui::GOLD << "    - " << ui::RESET << resp.body.substr(pos, end - pos) << "\n";
            found = true;
            pos = end + 1;
        }
        if (!found) ui::PrintInfo("No checkers found.");
    } else {
        ui::PrintError("Error fetching checkers.");
    }
    system("pause >nul");
}

void DeleteReport() {
    system("cls");
    ui::PrintHeader("DELETE REPORT");
    std::string drname = ui::GetInput("Report name (player name): ");
    if (drname.empty()) return;

    auto resp = HttpRequest(L"DELETE", L"/report/" + AnsiToWide(drname));
    if (resp.success) {
        ui::PrintSuccess("Deleted report: " + drname);
    } else {
        ui::PrintError("Report not found or error.");
    }
    system("pause >nul");
}

void ServerStatus() {
    system("cls");
    ui::PrintHeader("SERVER STATUS");
    
    ui::SpinnerWait(500, "Pinging server...");
    
    auto start = std::chrono::high_resolution_clock::now();
    auto resp = HttpRequest(L"GET", L"/health");
    auto end = std::chrono::high_resolution_clock::now();
    
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    if (resp.success) {
        ui::PrintSuccess("Status: ONLINE");
        ui::PrintInfo("Response time: " + std::to_string(duration) + "ms");
        ui::PrintInfo("URL: " + WideToAnsi(RENDER_URL));
    } else {
        ui::PrintError("Status: OFFLINE or SLEEPING");
        ui::PrintInfo("The server may be waking up (30-50s on free tier).");
    }
    system("pause >nul");
}

int main() {
    SetConsoleTitleW(L"NatsuXAK Scanner - Admin Panel");
    ui::EnableANSI();
    
    ui::PrintHeader("NatsuXAK Scanner - ADMIN PANEL");
    
    std::string nameInput = ui::GetInput("Enter Name: ");
    std::string keyInput = ui::GetInput("Enter Key: ");
    
    ADMIN_NAME = AnsiToWide(nameInput);
    ADMIN_KEY = AnsiToWide(keyInput);
    
    std::cout << "\n";
    if (!Authenticate()) {
        ui::PrintError("Access denied.");
        system("pause >nul");
        return 0;
    }
    
    while (true) {
        system("cls");
        ui::PrintHeader("NatsuXAK Scanner - ADMIN PANEL");
        std::cout << ui::GOLD << "    Logged in as: " << ui::RESET << nameInput << " (" << ROLE << ")\n\n";
        
        bool isMaster = (ROLE == "master");
        bool isOwner = (ROLE == "owner");
        
        std::cout << ui::GOLD << "    [1] " << ui::RESET << "Add Player (one-time use)\n";
        std::cout << ui::GOLD << "    [2] " << ui::RESET << "View Reports\n";
        
        if (isMaster || isOwner) {
            std::cout << ui::GOLD << "    [3] " << ui::RESET << "Add Checker\n";
            std::cout << ui::GOLD << "    [4] " << ui::RESET << "Remove Checker\n";
            std::cout << ui::GOLD << "    [5] " << ui::RESET << "List Checkers\n";
            if (isMaster) {
                std::cout << ui::GOLD << "    [6] " << ui::RESET << "Delete Report\n";
                std::cout << ui::GOLD << "    [7] " << ui::RESET << "Server Status\n";
                std::cout << ui::GOLD << "    [8] " << ui::RESET << "Exit\n";
            } else {
                std::cout << ui::GOLD << "    [6] " << ui::RESET << "Exit\n";
            }
        } else {
            std::cout << ui::GOLD << "    [3] " << ui::RESET << "Exit\n";
        }
        
        std::cout << "\n    " << ui::DARK_GOLD << std::string(36, '-') << "\n\n";
        std::string choice = ui::GetInput("Select: ");
        
        if (choice == "1") AddPlayer();
        else if (choice == "2") ViewReports();
        else if (isMaster || isOwner) {
            if (choice == "3") AddChecker();
            else if (choice == "4") RemoveChecker();
            else if (choice == "5") ListCheckers();
            
            if (isMaster) {
                if (choice == "6") DeleteReport();
                else if (choice == "7") ServerStatus();
                else if (choice == "8") break;
            } else {
                if (choice == "6") break;
            }
        } else {
            if (choice == "3") break;
        }
    }
    
    std::cout << "\n";
    ui::PrintSuccess("Admin panel closed.");
    return 0;
}
