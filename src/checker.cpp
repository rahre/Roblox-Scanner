// ============================================================================
// NatsuXAK Service SERVER
// Checker/Owner client for NatsuXAK Scanner
// Made by AK
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <winhttp.h>
#include <shlobj.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <bcrypt.h>

#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <sstream>
#include <thread>
#include <atomic>
#include <mutex>
#include <filesystem>
#include <algorithm>
#include <functional>

#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "shell32.lib")

// ============================================================================
// COMPILE-TIME STRING ENCRYPTION
// ============================================================================

template<size_t N>
struct EncStr {
    char data[N] = {0};
    static constexpr char KEY = 0x5A;
    constexpr EncStr(const char(&str)[N]) {
        for (size_t i = 0; i < N; i++)
            data[i] = str[i] ^ KEY;
    }
    std::string dec() const {
        std::string r(N - 1, 0);
        for (size_t i = 0; i < N - 1; i++)
            r[i] = data[i] ^ KEY;
        return r;
    }
};

template<size_t N>
struct EncStrW {
    wchar_t data[N] = {0};
    static constexpr wchar_t KEY = 0x5A;
    constexpr EncStrW(const wchar_t(&str)[N]) {
        for (size_t i = 0; i < N; i++)
            data[i] = str[i] ^ KEY;
    }
    std::wstring dec() const {
        std::wstring r(N - 1, 0);
        for (size_t i = 0; i < N - 1; i++)
            r[i] = data[i] ^ KEY;
        return r;
    }
};

#define ENC(s) []{ constexpr EncStr<sizeof(s)> e(s); return e; }().dec()
#define ENCW(s) []{ constexpr EncStrW<sizeof(s)/sizeof(wchar_t)> e(s); return e; }().dec()

// ============================================================================
// SOFTWARE PROTECTION — prevent cheaters from reverse-engineering this tool
// ============================================================================

static std::wstring Lower(const std::wstring& s) {
    std::wstring r = s;
    std::transform(r.begin(), r.end(), r.begin(), ::towlower);
    return r;
}

static bool ValidateParentProcess() {
    DWORD ppid = 0;
    DWORD myPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return true;

    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (pe.th32ProcessID == myPid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    if (ppid > 0) {
        if (Process32FirstW(snap, &pe)) {
            do {
                if (pe.th32ProcessID == ppid) {
                    std::wstring pname = Lower(pe.szExeFile);
                    CloseHandle(snap);
                    return (pname == L"explorer.exe" || pname == L"cmd.exe" ||
                            pname == L"powershell.exe" || pname == L"conhost.exe" ||
                            pname == L"windowsterminal.exe" || pname == L"wt.exe");
                }
            } while (Process32NextW(snap, &pe));
        }
    }
    CloseHandle(snap);
    return true;
}

static bool AntiDebugCheck() {
    // Basic debugger presence
    if (IsDebuggerPresent()) return true;

    // NtQueryInformationProcess — DebugPort
    typedef LONG(WINAPI* pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pNtQIP NtQIP = (pNtQIP)GetProcAddress(hNtdll, "NtQueryInformationProcess");
        if (NtQIP) {
            ULONG_PTR debugPort = 0;
            if (NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr) == 0) {
                if (debugPort != 0) return true;
            }
        }
    }

    // Hardware breakpoint detection
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (GetThreadContext(GetCurrentThread(), &ctx)) {
        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
    }

    // PEB NtGlobalFlag
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    if (pPeb) {
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0xBC);
#ifndef _WIN64
        ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0x68);
#endif
        if (ntGlobalFlag & 0x70) return true;
    }

    // Timing attack
    LARGE_INTEGER freq, start, end;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&start);
    Sleep(1);
    QueryPerformanceCounter(&end);
    double elapsed = (double)(end.QuadPart - start.QuadPart) / freq.QuadPart;
    if (elapsed > 0.5) return true;

    // RE tool process scan
    const wchar_t* reTools[] = {
        L"x64dbg.exe", L"x32dbg.exe", L"ollydbg.exe", L"ida.exe", L"ida64.exe",
        L"idag.exe", L"idag64.exe", L"idaw.exe", L"idaw64.exe", L"idaq.exe",
        L"idaq64.exe", L"windbg.exe", L"ghidra.exe", L"ghidrarun.exe",
        L"processhacker.exe", L"procmon.exe", L"procmon64.exe",
        L"wireshark.exe", L"fiddler.exe", L"httpdebugger.exe",
        L"cheatengine-x86_64.exe", L"cheatengine-i386.exe",
        L"dnspy.exe", L"de4dot.exe", L"ilspy.exe",
        L"pestudio.exe", L"scylla.exe", L"scylla_x64.exe", L"scylla_x86.exe",
        L"protection_id.exe", L"importrec.exe",
        nullptr
    };

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe2; pe2.dwSize = sizeof(pe2);
        if (Process32FirstW(hSnap, &pe2)) {
            do {
                std::wstring exeName = Lower(pe2.szExeFile);
                for (int i = 0; reTools[i]; i++) {
                    if (exeName == Lower(reTools[i])) {
                        CloseHandle(hSnap);
                        return true;
                    }
                }
            } while (Process32NextW(hSnap, &pe2));
        }
        CloseHandle(hSnap);
    }

    return false;
}

static void WipePEHeader() {
    DWORD oldProtect;
    HMODULE hMod = GetModuleHandleW(nullptr);
    if (VirtualProtect(hMod, 0x1000, PAGE_READWRITE, &oldProtect)) {
        ZeroMemory(hMod, 0x1000);
        VirtualProtect(hMod, 0x1000, oldProtect, &oldProtect);
    }
}

// TLS callback — fires before main()
#ifdef _MSC_VER
void NTAPI TlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        if (IsDebuggerPresent()) {
            MessageBoxW(nullptr, L"This application requires .NET Framework 4.8 or later.\nPlease install it from microsoft.com and try again.",
                        L"Runtime Error", MB_ICONERROR);
            ExitProcess(1);
        }
    }
}
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma comment(linker, "/INCLUDE:p_tls_callback")
#pragma const_seg(".CRT$XLB")
extern "C" PIMAGE_TLS_CALLBACK p_tls_callback = TlsCallback;
#pragma const_seg()
#endif

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

static std::wstring AnsiToWide(const std::string& s) {
    if (s.empty()) return L"";
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring w(sz - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], sz);
    return w;
}

static std::string WideToAnsi(const std::wstring& w) {
    if (w.empty()) return "";
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string s(sz - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

static std::wstring GetExeDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring dir(path);
    size_t pos = dir.find_last_of(L"\\");
    if (pos != std::wstring::npos) dir = dir.substr(0, pos);
    return dir;
}

static std::string JsonEscape(const std::string& s) {
    std::string r;
    for (char c : s) {
        if (c == '"') r += "\\\"";
        else if (c == '\\') r += "\\\\";
        else if (c == '\n') r += "\\n";
        else if (c == '\r') r += "\\r";
        else if (c == '\t') r += "\\t";
        else r += c;
    }
    return r;
}

std::string GenerateSecureKey() {
    BYTE bytes[16];
    BCryptGenRandom(NULL, bytes, sizeof(bytes), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    char hex[33] = {0};
    for (int i = 0; i < 16; i++) sprintf(hex + i * 2, "%02x", bytes[i]);
    return std::string("chk-") + hex;
}

// ============================================================================
// SERVER COMMUNICATION
// ============================================================================

static const std::wstring SERVER_HOST = ENCW(L"roblox-scanner-hioo.onrender.com");
static const INTERNET_PORT SERVER_PORT = INTERNET_DEFAULT_HTTPS_PORT;
static const DWORD SERVER_FLAGS = WINHTTP_FLAG_SECURE;

struct ServerResponse {
    bool success;
    int status;
    std::string body;
};

ServerResponse HttpRequest(const std::wstring& method, const std::wstring& path,
                           const std::string& postBody = "",
                           const std::vector<std::pair<std::wstring, std::wstring>>& headers = {}) {
    ServerResponse resp = {false, 0, ""};

    HINTERNET hSession = WinHttpOpen(ENCW(L"NatsuXAKService/5.0").c_str(),
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return resp;

    // 60-second timeout for cold starts
    WinHttpSetTimeouts(hSession, 60000, 60000, 60000, 60000);

    HINTERNET hConnect = WinHttpConnect(hSession, SERVER_HOST.c_str(), SERVER_PORT, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return resp; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, method.c_str(), path.c_str(),
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, SERVER_FLAGS);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return resp; }

    // Add custom headers
    for (const auto& h : headers) {
        std::wstring hdr = h.first + L": " + h.second;
        WinHttpAddRequestHeaders(hRequest, hdr.c_str(), -1, WINHTTP_ADDREQ_FLAG_ADD);
    }

    BOOL sent;
    if (!postBody.empty()) {
        WinHttpAddRequestHeaders(hRequest, L"Content-Type: application/json", -1, WINHTTP_ADDREQ_FLAG_ADD);
        sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            (LPVOID)postBody.c_str(), (DWORD)postBody.size(), (DWORD)postBody.size(), 0);
    } else {
        sent = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
            WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
    }

    if (sent && WinHttpReceiveResponse(hRequest, nullptr)) {
        DWORD statusCode = 0, sz = sizeof(statusCode);
        WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &sz, WINHTTP_NO_HEADER_INDEX);
        resp.status = statusCode;

        DWORD bytesAvail = 0;
        do {
            WinHttpQueryDataAvailable(hRequest, &bytesAvail);
            if (bytesAvail > 0) {
                char* buf = new char[bytesAvail + 1];
                DWORD bytesRead = 0;
                WinHttpReadData(hRequest, buf, bytesAvail, &bytesRead);
                buf[bytesRead] = 0;
                resp.body += std::string(buf, bytesRead);
                delete[] buf;
            }
        } while (bytesAvail > 0);

        resp.success = (statusCode >= 200 && statusCode < 300);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);
    return resp;
}

ServerResponse HttpRequestWithRetry(const std::wstring& method, const std::wstring& path,
                                     const std::string& postBody = "",
                                     const std::vector<std::pair<std::wstring, std::wstring>>& headers = {},
                                     int maxRetries = 3) {
    for (int attempt = 0; attempt < maxRetries; attempt++) {
        auto resp = HttpRequest(method, path, postBody, headers);
        if (resp.success || resp.status == 403 || resp.status == 404) return resp;

        if (attempt < maxRetries - 1) {
            const char* dots[] = {".", "..", "..."};
            std::cout << "    Waking up server" << dots[attempt % 3] << "\r" << std::flush;
            Sleep(10000);
        }
    }
    return {false, 0, ""};
}

// ============================================================================
// HARDWARE ID
// ============================================================================

static std::string GetHWID() {
    HKEY hKey;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0, KEY_READ | KEY_WOW64_64KEY, &hKey) == ERROR_SUCCESS) {
        char value[256];
        DWORD size = sizeof(value);
        if (RegQueryValueExA(hKey, "MachineGuid", nullptr, nullptr, (LPBYTE)value, &size) == ERROR_SUCCESS) {
            RegCloseKey(hKey);
            return std::string(value);
        }
        RegCloseKey(hKey);
    }
    return "UNKNOWN_HWID";
}

// ============================================================================
// CREDENTIALS
// ============================================================================

struct Credentials {
    std::string name;
    std::string key;
    std::string role;
};

static std::wstring GetCredentialPath() {
    wchar_t appData[MAX_PATH];
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appData);
    std::wstring dir = std::wstring(appData) + L"\\NatsuXAKService";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir + L"\\login.txt";
}

static bool SaveCredentials(const Credentials& c) {
    std::ofstream f(WideToAnsi(GetCredentialPath()));
    if (!f.is_open()) return false;
    f << c.name << "\n" << c.key;
    f.close();
    return true;
}

static Credentials LoadCredentials() {
    Credentials c;
    std::ifstream f(WideToAnsi(GetCredentialPath()));
    if (f.is_open()) {
        std::getline(f, c.name);
        std::getline(f, c.key);
        f.close();
    }
    return c;
}

// ============================================================================
// REPORT SYNC
// ============================================================================

static std::wstring GetReportsDir() {
    std::wstring dir = GetExeDirectory() + L"\\reports";
    CreateDirectoryW(dir.c_str(), nullptr);
    return dir;
}

static int SyncReports(const Credentials& creds) {
    std::vector<std::pair<std::wstring, std::wstring>> headers = {
        {L"X-Name", AnsiToWide(creds.name)},
        {L"X-Key", AnsiToWide(creds.key)}
    };

    auto resp = HttpRequest(L"GET", ENCW(L"/reports"), "", headers);
    if (!resp.success) return -1;

    // Parse JSON array of report names
    std::vector<std::string> reportNames;
    std::string body = resp.body;
    // Simple JSON array parser (["name1", "name2", ...])
    size_t pos = 0;
    while ((pos = body.find('"', pos)) != std::string::npos) {
        pos++;
        size_t end = body.find('"', pos);
        if (end == std::string::npos) break;
        reportNames.push_back(body.substr(pos, end - pos));
        pos = end + 1;
    }

    std::wstring reportsDir = GetReportsDir();
    int synced = 0;

    for (const auto& name : reportNames) {
        std::wstring localPath = reportsDir + L"\\" + AnsiToWide(name) + L".txt";
        if (std::filesystem::exists(localPath)) continue;

        std::wstring rptPath = ENCW(L"/report/") + AnsiToWide(name);
        auto rptResp = HttpRequest(L"GET", rptPath, "", headers);
        if (rptResp.success) {
            std::ofstream f(WideToAnsi(localPath));
            if (f.is_open()) {
                f << rptResp.body;
                f.close();
                synced++;
            }
        }
    }

    return synced;
}

// ============================================================================
// BACKGROUND POLLING
// ============================================================================

static std::atomic<bool> g_newReportFlag{false};
static std::atomic<bool> g_stopPolling{false};
static std::string g_lastReportAlert;
static std::mutex g_alertMutex;

void PollForReports(const Credentials& creds) {
    while (!g_stopPolling.load()) {
        Sleep(15000);
        if (g_stopPolling.load()) break;

        int synced = SyncReports(creds);
        if (synced > 0) {
            std::lock_guard<std::mutex> lock(g_alertMutex);
            g_lastReportAlert = "    [!] " + std::to_string(synced) + " new report(s) synced!";
            g_newReportFlag.store(true);
        }
    }
}

// ============================================================================
// MAIN APPLICATION
// ============================================================================

int main() {
    // Software protection checks
    if (AntiDebugCheck() || !ValidateParentProcess()) {
        MessageBoxW(nullptr,
            L"This application requires .NET Framework 4.8 or later.\nPlease install it from microsoft.com and try again.",
            L"Runtime Error", MB_ICONERROR);
        return 1;
    }

    WipePEHeader();

    SetConsoleTitleW(ENCW(L"NatsuXAK Service Panel").c_str());
    system("color 06");

    std::cout << "\n";
    std::cout << "    ========================================================\n";
    std::cout << "                   NatsuXAK Service SERVER\n";
    std::cout << "                   Made by AK and Natsu\n";
    std::cout << "    ========================================================\n\n";

    // Try saved credentials
    Credentials creds = LoadCredentials();
    creds.key = GetHWID();
    bool authenticated = false;

    if (!creds.name.empty()) {
        std::cout << "    Saved login found: " << creds.name << "\n";
        std::cout << "    Authenticating (HWID Lock)...\n";

        std::wstring authPath = ENCW(L"/auth?name=") + AnsiToWide(creds.name) +
                                ENCW(L"&key=") + AnsiToWide(creds.key);
        auto resp = HttpRequestWithRetry(L"GET", authPath);
        if (resp.success) {
            // Extract role from JSON
            size_t rpos = resp.body.find("\"role\"");
            if (rpos != std::string::npos) {
                size_t q1 = resp.body.find('"', rpos + 6);
                size_t q2 = resp.body.find('"', q1 + 1);
                if (q1 != std::string::npos && q2 != std::string::npos) {
                    creds.role = resp.body.substr(q1 + 1, q2 - q1 - 1);
                    authenticated = true;
                }
            }
        }
    }

    if (!authenticated) {
        std::cout << "    Enter Name: ";
        std::getline(std::cin, creds.name);
        std::cout << "\n    Authenticating and Locking to HWID...\n";

        std::wstring authPath = ENCW(L"/auth?name=") + AnsiToWide(creds.name) +
                                ENCW(L"&key=") + AnsiToWide(creds.key);
        auto resp = HttpRequestWithRetry(L"GET", authPath);
        if (!resp.success) {
            std::cout << "    [-] Authentication failed. Access denied.\n";
            std::cout << "    Press any key to exit...\n";
            system("pause >nul");
            return 1;
        }

        size_t rpos = resp.body.find("\"role\"");
        if (rpos != std::string::npos) {
            size_t q1 = resp.body.find('"', rpos + 6);
            size_t q2 = resp.body.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos)
                creds.role = resp.body.substr(q1 + 1, q2 - q1 - 1);
        }

        if (creds.role.empty()) {
            std::cout << "    [-] Access denied.\n";
            system("pause >nul");
            return 1;
        }

        SaveCredentials(creds);
    }

    std::cout << "    [+] Welcome, " << creds.name << " [CONNECTED]\n";
    std::cout << "    Role: " << creds.role << "\n\n";

    // Initial report sync
    std::cout << "    Syncing reports...\n";
    int synced = SyncReports(creds);
    if (synced >= 0) {
        std::cout << "    [+] Synced " << synced << " report(s)\n\n";
    } else {
        std::cout << "    [!] Could not sync reports\n\n";
    }

    // Start background polling
    std::thread pollThread(PollForReports, creds);
    pollThread.detach();

    // Menu loop
    bool running = true;
    while (running) {
        // Check for new report alerts
        if (g_newReportFlag.exchange(false)) {
            std::lock_guard<std::mutex> lock(g_alertMutex);
            std::cout << "\n" << g_lastReportAlert << "\n";
            Sleep(1500);
        }

        system("cls");
        std::cout << "\n";
        std::cout << "    ========================================================\n";
        std::cout << "                   NatsuXAK Service SERVER\n";
        std::cout << "                   Made by AK and Natsu\n";
        std::cout << "    ========================================================\n\n";
        std::cout << "    Logged in: " << creds.name << " (" << creds.role << ") [CONNECTED]\n";

        bool isMaster = (creds.role == "master");
        bool isOwner = (creds.role == "owner");

        if (isMaster || isOwner) {
            std::cout << "    " << (isMaster ? "[ALL REPORTS]" : "[ALL REPORTS]") << "\n\n";
            std::cout << "    [1] Add Player (one-time use)\n";
            std::cout << "    [2] View Reports\n";
            std::cout << "    [3] Add Checker\n";
            std::cout << "    [4] Remove Checker\n";
            std::cout << "    [5] List Checkers\n";
            std::cout << "    [6] Exit\n";
            std::cout << "    --------------------------------------------------------\n";
            std::cout << "    Select: ";
        } else {
            std::cout << "    [YOUR REPORTS]\n\n";
            std::cout << "    [1] Add Player (one-time use)\n";
            std::cout << "    [2] View Reports\n";
            std::cout << "    [3] Exit\n";
            std::cout << "    --------------------------------------------------------\n";
            std::cout << "    Select: ";
        }

        std::string choice;
        std::getline(std::cin, choice);

        // ============================================================
        // ADD PLAYER
        // ============================================================
        if (choice == "1") {
            system("cls");
            std::cout << "\n    ADD PLAYER\n";
            std::cout << "    One-time use - scanner auto-deletes after scan.\n\n";
            std::cout << "    Player name: ";
            std::string playerName;
            std::getline(std::cin, playerName);
            if (playerName.empty()) continue;

            std::ostringstream j;
            j << "{\"auth_name\":\"" << JsonEscape(creds.name)
              << "\",\"auth_key\":\"" << JsonEscape(creds.key)
              << "\",\"player_name\":\"" << JsonEscape(playerName) << "\"}";

            auto resp = HttpRequestWithRetry(L"POST", ENCW(L"/player/add"), j.str());
            if (resp.success) {
                std::cout << "\n    [+] Added: " << playerName << "\n";
                std::cout << "    [+] Send them scanner.exe to run.\n";
                std::cout << "    [+] Report comes back automatically.\n";
            } else {
                std::cout << "\n    [-] Error adding player.\n";
            }
            std::cout << "\n    Press any key...\n";
            system("pause >nul");
        }
        // ============================================================
        // VIEW REPORTS
        // ============================================================
        else if (choice == "2") {
            system("cls");
            std::cout << "\n    SCAN REPORTS\n";
            std::cout << "    ----------------------------------------\n\n";

            std::vector<std::pair<std::wstring, std::wstring>> headers = {
                {L"X-Name", AnsiToWide(creds.name)},
                {L"X-Key", AnsiToWide(creds.key)}
            };

            auto resp = HttpRequest(L"GET", ENCW(L"/reports"), "", headers);
            if (!resp.success) {
                std::cout << "    [-] Error fetching reports.\n";
                system("pause >nul");
                continue;
            }

            // Parse report names
            std::vector<std::string> names;
            std::string body = resp.body;
            size_t pos = 0;
            while ((pos = body.find('"', pos)) != std::string::npos) {
                pos++;
                size_t end = body.find('"', pos);
                if (end == std::string::npos) break;
                names.push_back(body.substr(pos, end - pos));
                pos = end + 1;
            }

            if (names.empty()) {
                std::cout << "    No reports yet.\n";
            } else {
                for (size_t i = 0; i < names.size(); i++) {
                    std::cout << "    " << (i + 1) << ". " << names[i] << "\n";
                }
            }

            std::cout << "\n    ----------------------------------------\n";
            std::cout << "    Enter report name to view (or 'back'): ";
            std::string rptName;
            std::getline(std::cin, rptName);
            if (rptName == "back" || rptName.empty()) continue;

            std::wstring rptPath = ENCW(L"/report/") + AnsiToWide(rptName);
            auto rptResp = HttpRequest(L"GET", rptPath, "", headers);
            if (rptResp.success) {
                std::cout << "\n    ========================================\n";
                std::cout << rptResp.body << "\n";
                std::cout << "    ========================================\n";
            } else if (rptResp.status == 403) {
                std::cout << "    [-] Access denied — not your report.\n";
            } else {
                std::cout << "    [-] Report not found.\n";
            }
            std::cout << "\n    Press any key...\n";
            system("pause >nul");
        }
        // ============================================================
        // ADD CHECKER (owner/master only)
        // ============================================================
        else if (choice == "3" && (isMaster || isOwner)) {
            system("cls");
            std::cout << "\n    ADD CHECKER\n\n";
            std::cout << "    Name: ";
            std::string checkerName;
            std::getline(std::cin, checkerName);
            if (checkerName.empty()) continue;

            std::cout << "    Role:\n";
            std::cout << "      [1] Checker (sees own reports only)\n";
            std::cout << "      [2] Owner (sees ALL reports, can manage checkers)\n";
            std::cout << "    Select: ";
            std::string roleChoice;
            std::getline(std::cin, roleChoice);
            std::string roleStr = (roleChoice == "2") ? "owner" : "checker";

            std::string newKey = GenerateSecureKey();

            std::ostringstream j;
            j << "{\"name\":\"" << JsonEscape(checkerName)
              << "\",\"key\":\"" << JsonEscape(newKey)
              << "\",\"role\":\"" << roleStr << "\"}";

            std::vector<std::pair<std::wstring, std::wstring>> headers = {
                {L"X-Name", AnsiToWide(creds.name)},
                {L"X-Key", AnsiToWide(creds.key)}
            };

            auto resp = HttpRequestWithRetry(L"POST", ENCW(L"/checker/add"), j.str(), headers);
            if (resp.success) {
                std::cout << "\n    [+] Added " << roleStr << ": " << checkerName << "\n";
                std::cout << "    [+] Key: " << newKey << "\n";
                std::cout << "    [+] Give them: NatsuXAK Service.exe + scanner.exe + this key\n";
            } else {
                std::cout << "\n    [-] Error adding checker.\n";
            }
            std::cout << "\n    Press any key...\n";
            system("pause >nul");
        }
        // ============================================================
        // REMOVE CHECKER (owner/master only)
        // ============================================================
        else if (choice == "4" && (isMaster || isOwner)) {
            system("cls");
            std::cout << "\n    REMOVE CHECKER\n\n";
            std::cout << "    Checker name: ";
            std::string rmName;
            std::getline(std::cin, rmName);
            if (rmName.empty()) continue;

            std::wstring delPath = ENCW(L"/checker/") + AnsiToWide(rmName);
            std::vector<std::pair<std::wstring, std::wstring>> headers = {
                {L"X-Name", AnsiToWide(creds.name)},
                {L"X-Key", AnsiToWide(creds.key)}
            };

            auto resp = HttpRequest(L"DELETE", delPath, "", headers);
            if (resp.success) {
                std::cout << "    [+] Removed: " << rmName << "\n";
            } else {
                std::cout << "    [-] Checker not found or error.\n";
            }
            std::cout << "\n    Press any key...\n";
            system("pause >nul");
        }
        // ============================================================
        // LIST CHECKERS (owner/master only)
        // ============================================================
        else if (choice == "5" && (isMaster || isOwner)) {
            system("cls");
            std::cout << "\n    CHECKERS\n";
            std::cout << "    ----------------------------------------\n\n";

            std::vector<std::pair<std::wstring, std::wstring>> headers = {
                {L"X-Name", AnsiToWide(creds.name)},
                {L"X-Key", AnsiToWide(creds.key)}
            };

            auto resp = HttpRequest(L"GET", ENCW(L"/checkers"), "", headers);
            if (resp.success) {
                std::string body = resp.body;
                size_t pos = 0;
                bool found = false;
                while ((pos = body.find('"', pos)) != std::string::npos) {
                    pos++;
                    size_t end = body.find('"', pos);
                    if (end == std::string::npos) break;
                    std::cout << "    - " << body.substr(pos, end - pos) << "\n";
                    pos = end + 1;
                    found = true;
                }
                if (!found) std::cout << "    No checkers found.\n";
            } else {
                std::cout << "    [-] Error fetching checkers.\n";
            }
            std::cout << "\n    Press any key...\n";
            system("pause >nul");
        }
        // ============================================================
        // EXIT
        // ============================================================
        else if ((choice == "6" && (isMaster || isOwner)) || (choice == "3" && !isMaster && !isOwner)) {
            running = false;
        }
    }

    g_stopPolling.store(true);
    std::cout << "\n    [+] NatsuXAK Service closed.\n";
    return 0;
}
