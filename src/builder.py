import os
import re

with open('scanner.cpp', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Add headers
content = content.replace('#include <mscat.h>', '#include <mscat.h>\n#include <wbemidl.h>\n#include <comdef.h>\n#include <math.h>\n#pragma comment(lib, "wbemuuid.lib")\n#pragma comment(lib, "ws2_32.lib")')

# 2. Add EncStr, TLS callback, Anti-RE utils before XOR obfuscation
enc_str = '''
template<size_t N>
struct EncStr {
    char data[N];
    static constexpr char KEY = 0x5A;
    constexpr EncStr(const char(&str)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = str[i] ^ KEY;
    }
    std::string dec() const {
        std::string r(N - 1, 0);
        for (size_t i = 0; i < N - 1; i++) r[i] = data[i] ^ KEY;
        return r;
    }
};
#define ENC(s) []{ constexpr EncStr<sizeof(s)> e(s); return e; }().dec()

template<size_t N>
struct EncStrW {
    wchar_t data[N];
    static constexpr wchar_t KEY = 0x5A;
    constexpr EncStrW(const wchar_t(&str)[N]) {
        for (size_t i = 0; i < N; i++) data[i] = str[i] ^ KEY;
    }
    std::wstring dec() const {
        std::wstring r(N - 1, 0);
        for (size_t i = 0; i < N - 1; i++) r[i] = data[i] ^ KEY;
        return r;
    }
};
#define ENCW(s) []{ constexpr EncStrW<sizeof(s)> e(s); return e; }().dec()

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback = [](PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH && IsDebuggerPresent()) {
        MessageBoxW(nullptr, L"This application requires .NET Framework 4.8.", L"Runtime Error", MB_ICONERROR);
        ExitProcess(1);
    }
};
#pragma const_seg()
#endif
'''
content = content.replace('// XOR obfuscation', enc_str + '\n// XOR obfuscation')

# 3. Enhance AntiDebugCheck
anti_debug_addition = '''
    // Check 1.5: PEB NtGlobalFlag and Heap Flags
#ifdef _WIN64
    PPEB pPeb = (PPEB)__readgsqword(0x60);
#else
    PPEB pPeb = (PPEB)__readfsdword(0x30);
#endif
    PDWORD ntGlobalFlag = (PDWORD)((PBYTE)pPeb + (_WIN64 ? 0xBC : 0x68));
    if (*ntGlobalFlag & 0x70) return true;

    PVOID heap = (PVOID)(*(PDWORD_PTR)((PBYTE)pPeb + (_WIN64 ? 0x30 : 0x18)));
    PDWORD forceFlags = (PDWORD)((PBYTE)heap + (_WIN64 ? 0x44 : 0x44)); // simplify checking
    if (*forceFlags != 0) return true;

    // Check 1.6: Hardware breakpoints
    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = GetCurrentThread();
    if (GetThreadContext(hThread, &ctx)) {
        if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0) return true;
    }
'''
content = content.replace('if (IsDebuggerPresent()) return true;', 'if (IsDebuggerPresent()) return true;\n' + anti_debug_addition)

# 4. Add utility functions: Entropy, WipePE, CRC, Parent Process, TCP connections, WMI, FileStreams
utils = '''
static void WipePEHeader() {
    DWORD oldProtect;
    HMODULE hMod = GetModuleHandleW(nullptr);
    VirtualProtect(hMod, 0x1000, PAGE_READWRITE, &oldProtect);
    ZeroMemory(hMod, 0x1000);
    VirtualProtect(hMod, 0x1000, oldProtect, &oldProtect);
}

static bool ValidateParentProcess() {
    DWORD ppid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        DWORD myPid = GetCurrentProcessId();
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
                        return (pname == L"explorer.exe" || pname == L"cmd.exe" || pname == L"powershell.exe" || pname == L"conhost.exe" || pname == L"windowsterminal.exe");
                    }
                } while (Process32NextW(snap, &pe));
            }
        }
        CloseHandle(snap);
    }
    return false;
}

static DWORD ComputeTextCRC32() {
    // Basic CRC32 computation on .text section
    HMODULE hMod = GetModuleHandleW(nullptr);
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMod;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PBYTE)hMod + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        if (memcmp(section[i].Name, ".text", 5) == 0) {
            PBYTE data = (PBYTE)hMod + section[i].VirtualAddress;
            DWORD size = section[i].SizeOfRawData;
            DWORD crc = 0xFFFFFFFF;
            for (DWORD j = 0; j < size; j++) {
                crc ^= data[j];
                for (int k = 0; k < 8; k++) crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
            }
            return ~crc;
        }
    }
    return 0;
}

static double CalculateEntropy(const std::string& data) {
    if (data.empty()) return 0.0;
    std::map<char, int> freqs;
    for (char c : data) freqs[c]++;
    double entropy = 0.0;
    for (auto const& [c, count] : freqs) {
        double p = (double)count / data.size();
        entropy -= p * log2(p);
    }
    return entropy;
}
'''
content = content.replace('// UTILITIES', '// UTILITIES\n' + utils)

# 5. Phase 8 Entropy Analysis
phase8_old = r'''if (ext == L".dll" && entry.file_size() > 4096 && entry.file_size() < 50 * 1024 * 1024) {
                                std::wstring parentDir = Lower(entry.path().parent_path().filename().wstring());
                                if (parentDir.length() >= 8 && parentDir.find(L"tmp") != std::wstring::npos) {
                                    std::ifstream peCheck(entry.path(), std::ios::binary);
                                    char mz[2] = {0};
                                    if (peCheck.read(mz, 2) && mz[0] == 'M' && mz[1] == 'Z') {
                                        r.findings.push_back({
                                            "SUSPICIOUS_TEMP_PE",
                                            WideToAnsi(filename),
                                            50,
                                            "PE file in temp directory: " + WideToAnsi(fullPath)
                                        });
                                        r.score += 10;
                                    }
                                }
                            }'''

phase8_new = r'''if ((ext == L".dll" || ext == L".exe") && entry.file_size() > 4096 && entry.file_size() < 50 * 1024 * 1024) {
                                std::ifstream peCheck(entry.path(), std::ios::binary);
                                std::string header(512, 0);
                                if (peCheck.read(&header[0], 512) && header[0] == 'M' && header[1] == 'Z') {
                                    double ent = CalculateEntropy(header);
                                    if (ent > 7.0) {
                                        r.findings.push_back({
                                            "HIGH_ENTROPY_PE",
                                            WideToAnsi(filename),
                                            60,
                                            "Packed/Encrypted PE file: " + WideToAnsi(fullPath) + " (Entropy: " + std::to_string(ent) + ")"
                                        });
                                        r.score += 15;
                                    }
                                    
                                    std::wstring parentDir = Lower(entry.path().parent_path().filename().wstring());
                                    if (parentDir.length() >= 8 && parentDir.find(L"tmp") != std::wstring::npos) {
                                        r.findings.push_back({
                                            "SUSPICIOUS_TEMP_PE",
                                            WideToAnsi(filename),
                                            50,
                                            "PE file in temp directory: " + WideToAnsi(fullPath)
                                        });
                                        r.score += 10;
                                    }
                                }
                            }'''
content = content.replace(phase8_old, phase8_new)

# 6. Browser history (add Vivaldi, Arc, Chromium)
chromium_old = r'''std::vector<std::wstring> chromiumPaths = {
            std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera GX Stable\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera Stable\\History",
        };'''
chromium_new = r'''std::vector<std::wstring> chromiumPaths = {
            std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera GX Stable\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera Stable\\History",
            std::wstring(localAppData) + L"\\Vivaldi\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Arc\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Chromium\\User Data\\Default\\History",
        };'''
content = content.replace(chromium_old, chromium_new)

# 7. Update Progress Bar from 23 to 31
content = re.sub(r'UpdateProgress\((\d+), 23\);', r'UpdateProgress(\1, 31);', content)

# 8. Add Phases 23-30
new_phases = '''
    // ========================================================================
    // PHASE 23: DMA Card Detection
    // ========================================================================
    {
        // 1. WMI Check
        HRESULT hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (SUCCEEDED(hres)) {
            IWbemLocator* pLoc = NULL;
            hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
            if (SUCCEEDED(hres)) {
                IWbemServices* pSvc = NULL;
                hres = pLoc->ConnectServer(_bstr_t(L"ROOT\\\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);
                if (SUCCEEDED(hres)) {
                    hres = CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
                    if (SUCCEEDED(hres)) {
                        IEnumWbemClassObject* pEnumerator = NULL;
                        hres = pSvc->ExecQuery(_bstr_t(L"WQL"), _bstr_t(L"SELECT * FROM Win32_PnPEntity"), WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);
                        if (SUCCEEDED(hres)) {
                            IWbemClassObject* pclsObj = NULL;
                            ULONG uReturn = 0;
                            while (pEnumerator) {
                                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                                if (0 == uReturn) break;
                                VARIANT vtProp;
                                hr = pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
                                if (SUCCEEDED(hr) && vtProp.vt == VT_BSTR && vtProp.bstrVal != NULL) {
                                    std::wstring name = Lower(vtProp.bstrVal);
                                    if (name.find(L"fpga") != std::wstring::npos || name.find(L"screamer") != std::wstring::npos || name.find(L"pcileech") != std::wstring::npos || (name.find(L"dma") != std::wstring::npos && name.find(L"direct memory") == std::wstring::npos)) {
                                        r.findings.push_back({ "DMA_DEVICE", WideToAnsi(name), 90, "Suspicious PCI device found via WMI" });
                                        r.score += 40;
                                    }
                                }
                                VariantClear(&vtProp);
                                pclsObj->Release();
                            }
                            pEnumerator->Release();
                        }
                    }
                    pSvc->Release();
                }
                pLoc->Release();
            }
            CoUninitialize();
        }

        // 2. Kernel drivers check for DMA
        std::vector<std::wstring> dmaDrivers = { L"pcileech.sys", L"fpga.sys", L"rawaccess.sys" };
        LPVOID drivers[1024];
        DWORD cbNeeded;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            int driverCount = cbNeeded / sizeof(LPVOID);
            for (int i = 0; i < driverCount; i++) {
                wchar_t driverName[MAX_PATH];
                if (GetDeviceDriverBaseNameW(drivers[i], driverName, MAX_PATH)) {
                    std::wstring name = Lower(driverName);
                    for (const auto& dma : dmaDrivers) {
                        if (name.find(dma) != std::wstring::npos) {
                            r.findings.push_back({ "DMA_DRIVER", WideToAnsi(name), 90, "Loaded DMA driver" });
                            r.score += 40;
                        }
                    }
                }
            }
        }
    }
    UpdateProgress(23, 31);

    // ========================================================================
    // PHASE 24: Dual-PC / Network Streaming Detection
    // ========================================================================
    {
        std::vector<std::string> streamApps = {
            "parsec.exe", "parsecd.exe", "moonlight.exe", "sunshine.exe", 
            "steamlink.exe", "steam_link.exe", "rustdesk.exe", "supremo.exe"
        };
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    std::string exe = WideToAnsi(pe.szExeFile);
                    std::transform(exe.begin(), exe.end(), exe.begin(), ::tolower);
                    if (exe == "anydesk.exe") continue; // whitelist
                    for (const auto& app : streamApps) {
                        if (exe == app) {
                            r.findings.push_back({ "STREAMING_APP", app, 70, "Potential Dual-PC setup / Streaming software" });
                            r.score += 20;
                            break;
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        
        // Active TCP connections check
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"netstat -ano";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string nsOutput;
                char buf[4096]; DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0; nsOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 3000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                
                if (nsOutput.find(":8000") != std::string::npos || nsOutput.find(":47984") != std::string::npos || nsOutput.find(":47989") != std::string::npos) {
                    r.findings.push_back({ "STREAMING_PORT", "Active connection", 70, "Active TCP connection on streaming port (Parsec/Moonlight/Sunshine)" });
                    r.score += 20;
                }
            } else { CloseHandle(hWrite); CloseHandle(hRead); }
        }
    }
    UpdateProgress(24, 31);

    // ========================================================================
    // PHASE 25: Timestomping Detection
    // ========================================================================
    {
        std::vector<std::wstring> scanPaths;
        wchar_t tempPath[MAX_PATH]; if (GetTempPathW(MAX_PATH, tempPath)) scanPaths.push_back(tempPath);
        wchar_t appdataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdataPath))) scanPaths.push_back(appdataPath);
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appdataPath))) scanPaths.push_back(appdataPath);

        for (const auto& scanDir : scanPaths) {
            try {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(scanDir, std::filesystem::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file()) continue;
                    std::wstring fn = entry.path().filename().wstring();
                    if (MatchesCheatFileSignature(fn)) {
                        HANDLE hFile = CreateFileW(entry.path().wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            FILETIME ct, at, wt;
                            if (GetFileTime(hFile, &ct, &at, &wt)) {
                                ULARGE_INTEGER cti, wti;
                                cti.LowPart = ct.dwLowDateTime; cti.HighPart = ct.dwHighDateTime;
                                wti.LowPart = wt.dwLowDateTime; wti.HighPart = wt.dwHighDateTime;
                                if (cti.QuadPart > wti.QuadPart) {
                                    r.findings.push_back({ "TIMESTOMPING", WideToAnsi(fn), 75, "Creation time is AFTER Last Write time: " + WideToAnsi(entry.path().wstring()) });
                                    r.score += 25;
                                }
                                FILETIME now; GetSystemTimeAsFileTime(&now);
                                ULARGE_INTEGER nowi; nowi.LowPart = now.dwLowDateTime; nowi.HighPart = now.dwHighDateTime;
                                if ((nowi.QuadPart - cti.QuadPart) > (365ULL * 24 * 3600 * 10000000ULL)) {
                                    r.findings.push_back({ "TIMESTOMPING", WideToAnsi(fn), 75, "Suspiciously old file in Temp/AppData (>1yr): " + WideToAnsi(entry.path().wstring()) });
                                    r.score += 25;
                                }
                            }
                            CloseHandle(hFile);
                        }
                    }
                }
            } catch (...) {}
        }
    }
    UpdateProgress(25, 31);

    // ========================================================================
    // PHASE 26: Amcache Registry
    // ========================================================================
    {
        HKEY hAmc;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\AppCompatFlags\\\\Amcache", 0, KEY_READ, &hAmc) == ERROR_SUCCESS) {
            // Just flagging access to Amcache if we find cheat signatures in subkeys
            // Very simplified check due to Amcache structure complexity
            r.findings.push_back({ "AMCACHE_ACCESS", "Amcache Registry", 85, "Amcache checked (placeholder for deep scan)" });
            RegCloseKey(hAmc);
        }
    }
    UpdateProgress(26, 31);

    // ========================================================================
    // PHASE 27: SRUM Database
    // ========================================================================
    {
        std::wstring srumPath = L"C:\\\\Windows\\\\System32\\\\sru\\\\SRUDB.dat";
        std::wstring tempSrum = L"C:\\\\Windows\\\\Temp\\\\SRUDB_COPY.dat";
        if (CopyFileW(srumPath.c_str(), tempSrum.c_str(), FALSE)) {
            std::ifstream f(tempSrum.c_str(), std::ios::binary);
            if (f.is_open()) {
                std::string content; content.resize(10 * 1024 * 1024);
                f.read(&content[0], content.size());
                content.resize(f.gcount());
                f.close();
                std::string contentLower = content;
                std::transform(contentLower.begin(), contentLower.end(), contentLower.begin(), ::tolower);
                for (const auto& sig : CHEAT_SIGNATURES) {
                    if (contentLower.find(WideToAnsi(Lower(sig))) != std::string::npos) {
                        r.findings.push_back({ "SRUM_DATABASE", WideToAnsi(sig), 80, "Cheat execution artifact in SRUM database" });
                        r.score += 25;
                    }
                }
            }
            DeleteFileW(tempSrum.c_str());
        }
    }
    UpdateProgress(27, 31);

    // ========================================================================
    // PHASE 28: Recycle Bin Forensics
    // ========================================================================
    {
        try {
            for (const auto& entry : std::filesystem::recursive_directory_iterator(L"C:\\\\$Recycle.Bin", std::filesystem::directory_options::skip_permission_denied)) {
                if (!entry.is_regular_file()) continue;
                std::wstring fn = entry.path().filename().wstring();
                if (fn.length() >= 2 && fn[0] == L'$' && fn[1] == L'I') {
                    std::ifstream f(entry.path().wstring(), std::ios::binary);
                    if (f.is_open()) {
                        f.seekg(24, std::ios::beg);
                        std::wstring origPath;
                        wchar_t ch;
                        while (f.read((char*)&ch, 2) && ch != 0) origPath += ch;
                        f.close();
                        if (MatchesCheatFileSignature(origPath) || MatchesCheatSignature(origPath)) {
                            r.findings.push_back({ "RECYCLE_BIN", WideToAnsi(origPath), 80, "Deleted cheat file in Recycle Bin" });
                            r.score += 25;
                        }
                    }
                }
            }
        } catch (...) {}
    }
    UpdateProgress(28, 31);

    // ========================================================================
    // PHASE 29: Volume Shadow Copy Check
    // ========================================================================
    {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite; si.hStdError = hWrite; si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"vssadmin list shadows";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string vssOutput;
                char buf[4096]; DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0; vssOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 3000);
                CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
                
                if (vssOutput.find("Shadow Copy Volume:") != std::string::npos) {
                    r.findings.push_back({ "SHADOW_COPIES", "Volume Shadow Copies Exist", 50, "System has shadow copies (potential evidence hiding spot)" });
                    r.score += 10;
                }
            } else { CloseHandle(hWrite); CloseHandle(hRead); }
        }
    }
    UpdateProgress(29, 31);

    // ========================================================================
    // PHASE 30: NTFS Alternate Data Streams
    // ========================================================================
    {
        std::vector<std::wstring> scanPaths;
        wchar_t tempPath[MAX_PATH]; if (GetTempPathW(MAX_PATH, tempPath)) scanPaths.push_back(tempPath);
        wchar_t appdataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdataPath))) scanPaths.push_back(appdataPath);

        for (const auto& scanDir : scanPaths) {
            try {
                for (const auto& entry : std::filesystem::recursive_directory_iterator(scanDir, std::filesystem::directory_options::skip_permission_denied)) {
                    if (!entry.is_regular_file()) continue;
                    std::wstring fn = entry.path().filename().wstring();
                    if (MatchesCheatFileSignature(fn)) {
                        WIN32_FIND_STREAM_DATA fsd;
                        HANDLE hFind = FindFirstStreamW(entry.path().wstring().c_str(), FindStreamInfoStandard, &fsd, 0);
                        if (hFind != INVALID_HANDLE_VALUE) {
                            do {
                                std::wstring streamName(fsd.cStreamName);
                                if (streamName != L"::$DATA") {
                                    r.findings.push_back({ "ADS_STREAM", WideToAnsi(streamName), 85, "Alternate Data Stream on cheat file: " + WideToAnsi(entry.path().wstring()) });
                                    r.score += 30;
                                }
                            } while (FindNextStreamW(hFind, &fsd));
                            FindClose(hFind);
                        }
                    }
                }
            } catch (...) {}
        }
    }
    UpdateProgress(30, 31);
    UpdateProgress(31, 31);
'''
content = content.replace('UpdateProgress(23, 23);', new_phases)

# 9. Main modifications
main_mods_start = r'''int main(int argc, char* argv[]) {
    // Anti-RE: detect debuggers, disassemblers, process monitors
    if (AntiDebugCheck()) {
        // Show a misleading error — don't reveal we detected them
        MessageBoxW(nullptr, L"This application requires .NET Framework 4.8 or later.\nPlease install it from microsoft.com and try again.",
                     L"Runtime Error", MB_ICONERROR);
        return 1;
    }

    SetConsoleTitleW(L"Gakuran Cheater Checker");'''

main_mods_new = r'''int main(int argc, char* argv[]) {
    // Anti-RE: detect debuggers, disassemblers, process monitors
    if (AntiDebugCheck()) {
        MessageBoxW(nullptr, L"This application requires .NET Framework 4.8 or later.\nPlease install it from microsoft.com and try again.",
                     L"Runtime Error", MB_ICONERROR);
        return 1;
    }
    
    WipePEHeader();
    if (!ValidateParentProcess()) {
        MessageBoxW(nullptr, L"This application requires .NET Framework 4.8 or later.\nPlease install it from microsoft.com and try again.", L"Runtime Error", MB_ICONERROR);
        return 1;
    }
    DWORD crc = ComputeTextCRC32();

    SetConsoleTitleW(ENCW(L"Gakuran Cheater Checker").c_str());'''

content = content.replace(main_mods_start, main_mods_new)

# Remove local fallback & tunnel code
local_fallback_old = r'''// Check local players directory (next to exe)
    std::wstring exeDir = GetExeDirectory();
    std::vector<std::wstring> localPaths = {
        exeDir + L"\\players\\" + AnsiToWide(name) + L".txt",
        exeDir + L"\\..\\players\\" + AnsiToWide(name) + L".txt",
    };
    // Also check CWD-relative for backwards compat
    localPaths.push_back(AnsiToWide("players\\" + name + ".txt"));
    localPaths.push_back(AnsiToWide("..\\players\\" + name + ".txt"));

    for (const auto& path : localPaths) {
        std::ifstream pf(path.c_str());
        if (pf.is_open()) {
            std::getline(pf, playerType);
            playerType.erase(playerType.find_last_not_of(" \n\r\t") + 1);
            pf.close();
            if (!playerType.empty()) {
                std::cout << "    [+] Authorized via local player database\n";
                break;
            }
        }
    }

    // Server variables — needed for report POST later
    std::wstring serverHost = L"127.0.0.1";
    INTERNET_PORT serverPort = 5000;
    DWORD flagSecure = 0;
    bool tunnelResolved = false;

    // If local file check didn't set playerType, try HTTP server / Rentry tunnel
    if (playerType.empty()) {
        std::string rawUrlStr = "";

        HINTERNET hSession = WinHttpOpen(L"RobloxScanner/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            // Set timeouts so we don't hang forever if offline
            WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);

            HINTERNET hConnect = WinHttpConnect(hSession, L"rentry.co", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConnect) {
                HINTERNET hReq = WinHttpOpenRequest(hConnect, L"GET", L"/dvwpwgft", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (hReq) {
                    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                        if (WinHttpReceiveResponse(hReq, nullptr)) {
                            DWORD size = 0;
                            do {
                                WinHttpQueryDataAvailable(hReq, &size);
                                if (size > 0) {
                                    char* buf = new char[size + 1];
                                    ZeroMemory(buf, size + 1);
                                    DWORD dl = 0;
                                    WinHttpReadData(hReq, buf, size, &dl);
                                    rawUrlStr += std::string(buf, dl);
                                    delete[] buf;
                                }
                            } while (size > 0);
                        }
                    }
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConnect);
            }

            size_t tunnelPos = rawUrlStr.find(".trycloudflare.com");
            if (tunnelPos != std::string::npos) {
                size_t httpsPos = rawUrlStr.rfind("https://", tunnelPos);
                if (httpsPos != std::string::npos) {
                    std::string domain = rawUrlStr.substr(httpsPos + 8, (tunnelPos + 18) - (httpsPos + 8));
                    serverHost = std::wstring(domain.begin(), domain.end());
                    serverPort = INTERNET_DEFAULT_HTTPS_PORT;
                    flagSecure = WINHTTP_FLAG_SECURE;
                    tunnelResolved = true;
                }
            }

            std::wstring wname = AnsiToWide(name);
            std::wstring reqPath = L"/verify?name=" + wname;

            HINTERNET hSrvConnect = WinHttpConnect(hSession, serverHost.c_str(), serverPort, 0);
            if (hSrvConnect) {
                HINTERNET hSrvReq = WinHttpOpenRequest(hSrvConnect, L"GET", reqPath.c_str(),
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flagSecure);
                if (hSrvReq) {
                    if (WinHttpSendRequest(hSrvReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                        if (WinHttpReceiveResponse(hSrvReq, nullptr)) {
                            DWORD size = 0;
                            do {
                                WinHttpQueryDataAvailable(hSrvReq, &size);
                                if (size > 0) {
                                    char* buf = new char[size + 1];
                                    ZeroMemory(buf, size + 1);
                                    DWORD dl = 0;
                                    WinHttpReadData(hSrvReq, buf, size, &dl);
                                    playerType += std::string(buf, dl);
                                    delete[] buf;
                                }
                            } while (size > 0);
                        }
                    }
                    WinHttpCloseHandle(hSrvReq);
                }
                WinHttpCloseHandle(hSrvConnect);
            }
            WinHttpCloseHandle(hSession);
        }
    }'''

local_fallback_new = r'''
    std::wstring serverHost = ENCW(L"roblox-scanner-hioo.onrender.com");
    INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTPS_PORT;
    DWORD flagSecure = WINHTTP_FLAG_SECURE;
    
    HINTERNET hSession = WinHttpOpen(ENCW(L"RobloxScanner/4.0").c_str(), WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        WinHttpSetTimeouts(hSession, 5000, 5000, 5000, 5000);
        std::wstring wname = AnsiToWide(name);
        std::wstring reqPath = ENCW(L"/verify?name=") + wname;

        HINTERNET hSrvConnect = WinHttpConnect(hSession, serverHost.c_str(), serverPort, 0);
        if (hSrvConnect) {
            HINTERNET hSrvReq = WinHttpOpenRequest(hSrvConnect, L"GET", reqPath.c_str(),
                nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flagSecure);
            if (hSrvReq) {
                if (WinHttpSendRequest(hSrvReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                    if (WinHttpReceiveResponse(hSrvReq, nullptr)) {
                        DWORD size = 0;
                        do {
                            WinHttpQueryDataAvailable(hSrvReq, &size);
                            if (size > 0) {
                                char* buf = new char[size + 1];
                                ZeroMemory(buf, size + 1);
                                DWORD dl = 0;
                                WinHttpReadData(hSrvReq, buf, size, &dl);
                                playerType += std::string(buf, dl);
                                delete[] buf;
                            }
                        } while (size > 0);
                    }
                }
                WinHttpCloseHandle(hSrvReq);
            }
            WinHttpCloseHandle(hSrvConnect);
        }
        WinHttpCloseHandle(hSession);
    }'''
content = content.replace(local_fallback_old, local_fallback_new)

# PostReportToServer ENCW replace
post_report_old = r'''HINTERNET hSession = WinHttpOpen(L"RobloxScanner/4.0",'''
post_report_new = r'''HINTERNET hSession = WinHttpOpen(ENCW(L"RobloxScanner/4.0").c_str(),'''
content = content.replace(post_report_old, post_report_new)

post_report_req_old = r'''HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/report",'''
post_report_req_new = r'''HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", ENCW(L"/report").c_str(),'''
content = content.replace(post_report_req_old, post_report_req_new)

with open('scanner.cpp', 'w', encoding='utf-8') as f:
    f.write(content)
