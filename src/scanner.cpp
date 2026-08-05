#include <winsock2.h>
#include <windows.h>

#include <wintrust.h>
#include <softpub.h>
#include <wincrypt.h>
#include <winioctl.h>
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <winhttp.h>
#include <psapi.h>
#include <shlobj.h>
#include <intrin.h>
#include <winevt.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <filesystem>
#include <chrono>
#include <iomanip>
#include <algorithm>
#include <set>
#include <functional>
#include <map>
#include <ntstatus.h>
#include <mscat.h>
#include <wbemidl.h>
#include <comdef.h>
#include <math.h>
#include "ui.h"
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "ws2_32.lib")

#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "wevtapi.lib")

// ============================================================================
// CONFIGURATION
// ============================================================================

const int USN_LOOKBACK_HOURS = 24;
const int MAX_UNSIGNED_DLL_SCORE = 15;
const int SCAN_WINDOW_HOURS = 24;  // Only flag artifacts from the last 24 hours

// ============================================================================
// ANTI-REVERSE-ENGINEERING ??? Detect debuggers, disassemblers, RE tools
// ============================================================================


template<size_t N>
struct EncStr {
    char data[N] = {0};
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
    wchar_t data[N] = {0};
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
#define ENCW(s) []{ constexpr EncStrW<sizeof(s)/sizeof(wchar_t)> e(s); return e; }().dec()

#ifdef _MSC_VER
#pragma comment(linker, "/INCLUDE:_tls_used")
#pragma const_seg(".CRT$XLB")
extern "C" const PIMAGE_TLS_CALLBACK tls_callback = [](PVOID, DWORD reason, PVOID) {
    if (reason == DLL_PROCESS_ATTACH && IsDebuggerPresent()) {
        // Silently exit to prevent debugging, without showing a confusing fake .NET error
        ExitProcess(1);
    }
};
#pragma const_seg()
#endif

// XOR obfuscation for sensitive strings (Rentry URL, server info)
static std::string XorDecode(const char* data, int len, char key) {
    std::string result(len, 0);
    for (int i = 0; i < len; i++) result[i] = data[i] ^ key;
    return result;
}

static bool AntiDebugCheck() {
    // Check 1: IsDebuggerPresent
    if (IsDebuggerPresent()) return true;
    
    BOOL isDebuggerPresent = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDebuggerPresent);
    if (isDebuggerPresent) return true;

    // Check 1.5: PEB NtGlobalFlag and Heap Flags
#ifdef _WIN64
    PBYTE pPeb = (PBYTE)__readgsqword(0x60);
#else
    PBYTE pPeb = (PBYTE)__readfsdword(0x30);
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


    // Check 2: NtQueryInformationProcess ??? DebugPort
    typedef LONG (NTAPI *pNtQIP)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    pNtQIP NtQIP = (pNtQIP)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess");
    if (NtQIP) {
        ULONG_PTR debugPort = 0;
        if (NtQIP(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr) == 0 && debugPort != 0)
            return true;
    }

    // Check 3: Timing attack ??? debuggers slow execution
    LARGE_INTEGER freq, t1, t2;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&t1);
    Sleep(1);
    QueryPerformanceCounter(&t2);
    double elapsed = (double)(t2.QuadPart - t1.QuadPart) / freq.QuadPart;
    if (elapsed > 0.5) return true;  // Should be ~1ms, not 500ms+

    // Check 4: Check for known RE tool windows
    const wchar_t* reWindows[] = {
        L"x64dbg", L"x32dbg", L"OllyDbg", L"IDA",
        L"Ghidra", L"dnSpy", L"Cheat Engine",
        L"Process Hacker", L"Process Monitor",
        nullptr
    };
    for (int i = 0; reWindows[i]; i++) {
        if (FindWindowW(nullptr, reWindows[i])) return true;
    }

    // Check 5: Check for common RE tool processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring name(pe.szExeFile);
                std::transform(name.begin(), name.end(), name.begin(), ::tolower);
                if (name == L"x64dbg.exe" || name == L"x32dbg.exe" ||
                    name == L"ollydbg.exe" || name == L"ida.exe" ||
                    name == L"ida64.exe" || name == L"idaq.exe" ||
                    name == L"ghidra.exe" || name == L"dnspy.exe" ||
                    name == L"de4dot.exe" || name == L"dumpcap.exe" ||
                    name == L"wireshark.exe" || name == L"fiddler.exe" ||
                    name == L"httpdebuggerpro.exe" || name == L"procmon.exe" ||
                    name == L"procmon64.exe") {
                    CloseHandle(snap);
                    return true;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    return false;
}

// ============================================================================
// NATIVE NT API TYPES (for path resolution)
// ============================================================================

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

extern "C" {
    NTSTATUS NTAPI RtlDosPathNameToNtPathName_U(PCWSTR DosPathName, PUNICODE_STRING NtPathName, PWSTR* FilePart, PVOID RelativeName);
    VOID NTAPI RtlFreeUnicodeString(PUNICODE_STRING UnicodeString);
}

// ============================================================================
// CATALOG SIGNING ??? Dynamic loading (MSYS2 headers don't include CryptCATAdmin*)
// ============================================================================

typedef HANDLE HCATINFO;

// struct defined in mscat.h

typedef BOOL (WINAPI *pfnCryptCATAdminAcquireContext)(HCATINFO*, const GUID*, DWORD);
typedef BOOL (WINAPI *pfnCryptCATAdminReleaseContext)(HCATINFO, DWORD);
typedef HCATINFO (WINAPI *pfnCryptCATAdminEnumCatalogFromHash)(HCATINFO, const BYTE*, DWORD, DWORD, HCATINFO*);
typedef BOOL (WINAPI *pfnCryptCATAdminReleaseCatalogContext)(HCATINFO, HCATINFO, DWORD);
typedef BOOL (WINAPI *pfnCryptCATCatalogInfoFromContext)(HCATINFO, CATALOG_INFO*, DWORD);
typedef BOOL (WINAPI *pfnCryptCATAdminCalcHashFromFileHandle)(HANDLE, DWORD*, BYTE*, DWORD);

struct CatalogAPIs {
    HMODULE hWinTrust;
    pfnCryptCATAdminAcquireContext pAcquireContext;
    pfnCryptCATAdminReleaseContext pReleaseContext;
    pfnCryptCATAdminEnumCatalogFromHash pEnumCatalogFromHash;
    pfnCryptCATAdminReleaseCatalogContext pReleaseCatalogContext;
    pfnCryptCATCatalogInfoFromContext pCatalogInfoFromContext;
    pfnCryptCATAdminCalcHashFromFileHandle pCalcHashFromFileHandle;
};

CatalogAPIs LoadCatalogAPIs() {
    CatalogAPIs api = {0};
    api.hWinTrust = LoadLibraryW(L"wintrust.dll");
    if (api.hWinTrust) {
        api.pAcquireContext = (pfnCryptCATAdminAcquireContext)GetProcAddress(api.hWinTrust, "CryptCATAdminAcquireContext");
        api.pReleaseContext = (pfnCryptCATAdminReleaseContext)GetProcAddress(api.hWinTrust, "CryptCATAdminReleaseContext");
        api.pEnumCatalogFromHash = (pfnCryptCATAdminEnumCatalogFromHash)GetProcAddress(api.hWinTrust, "CryptCATAdminEnumCatalogFromHash");
        api.pReleaseCatalogContext = (pfnCryptCATAdminReleaseCatalogContext)GetProcAddress(api.hWinTrust, "CryptCATAdminReleaseCatalogContext");
        api.pCatalogInfoFromContext = (pfnCryptCATCatalogInfoFromContext)GetProcAddress(api.hWinTrust, "CryptCATCatalogInfoFromContext");
        api.pCalcHashFromFileHandle = (pfnCryptCATAdminCalcHashFromFileHandle)GetProcAddress(api.hWinTrust, "CryptCATAdminCalcHashFromFileHandle");
    }
    return api;
}

// ============================================================================
// KNOWN-CLEAN WINDOWS DLL WHITELIST
// These are Microsoft OS components that use catalog signing instead of
// embedded Authenticode. They fail WinVerifyTrust but are legitimate.
// ============================================================================

const std::set<std::wstring> WINDOWS_DLL_WHITELIST = {
    L"apphelp.dll", L"aclayers.dll", L"acgenral.dll", L"acspecfc.dll",
    L"winspool.drv", L"gdiplus.dll", L"opengl32.dll", L"glu32.dll",
    L"dinput8.dll", L"xinput1_4.dll", L"xinput1_3.dll", L"xinput9_1_0.dll",
    L"uxtheme.dll", L"dbghelp.dll", L"wininet.dll", L"comdlg32.dll",
    L"rasadhlp.dll", L"fwpuclnt.dll", L"dpapi.dll",
    L"dhcpcsvc6.dll", L"dhcpcsvc.dll", L"iconcodecservice.dll",
    L"napinsp.dll", L"pnrpnsp.dll", L"wshbth.dll", L"nlaapi.dll",
    L"winrnr.dll", L"atlthunk.dll", L"hid.dll",
    L"dwmapi.dll", L"userenv.dll", L"profapi.dll",
    L"d3d11.dll", L"d3d10warp.dll", L"d3d9.dll", L"dxgi.dll",
    L"d3dcompiler_47.dll", L"d2d1.dll", L"dwrite.dll",
    L"wlanapi.dll", L"wlanutil.dll", L"ondemandconnroutehelper.dll",
    L"winmm.dll", L"winmmbase.dll", L"devobj.dll",
    L"cryptsp.dll", L"rsaenh.dll", L"gpapi.dll",
    L"mswsock.dll", L"winnsi.dll", L"nsi.dll",
    L"version.dll", L"wtsapi32.dll", L"powrprof.dll",
    L"cfgmgr32.dll", L"cryptbase.dll", L"sspicli.dll",
    L"msasn1.dll", L"imagehlp.dll", L"dbgcore.dll",
    L"ntmarta.dll", L"samcli.dll", L"netutils.dll",
    L"dsreg.dll", L"msvcp_win.dll", L"win32u.dll",
    L"textinputframework.dll", L"coreuicomponents.dll",
    L"coremessaging.dll", L"wintypes.dll", L"twinapi.appcore.dll",
    L"inputhost.dll", L"propsys.dll", L"windows.storage.dll",
    L"shlwapi.dll", L"urlmon.dll", L"iertutil.dll",
    L"msctf.dll", L"oleaut32.dll", L"combase.dll",
    L"clbcatq.dll", L"audioses.dll", L"avrt.dll",
    L"resourcepolicyclient.dll", L"mfplat.dll",
    L"rtworkq.dll",
};

// ============================================================================
// KNOWN CHEAT SIGNATURES ??? used for process names, DLL names, BAM, USN, Prefetch
// These must be specific enough to not match legitimate software.
// "electron" removed ??? matches Discord, VS Code, Overwolf, CurseForge
// "inject"/"injector" removed ??? matches node_modules, Puppeteer, Playwright
// "exploit" removed ??? too generic
// "swift" removed ??? matches vk_swiftshader.dll
// "wave" removed ??? matches Opera GX underwave, qwave.dll
// "comet" removed ??? matches Minecraft cosmetics
// "panda" removed ??? matches Minecraft cosmetics
// "oxygen" removed ??? too generic
// "sentinel" removed ??? matches Windows Sentinel service
// "vape" removed ??? too many false matches, use exact name instead
// "aspect" removed ??? too generic
// "tempest" removed ??? too generic
// ============================================================================

const std::vector<std::wstring> CHEAT_SIGNATURES = {
    // Debuggers / RE tools
    L"cheatengine", L"cheat engine", L"processhacker", L"process hacker",
    L"x64dbg", L"x32dbg", L"ollydbg", L"dnspy", L"ida pro", L"ghidra",
    // Roblox exploits ??? executor names
    L"synapse x", L"synapsex", L"synapse z", L"synapsez",
    L"krnl", L"fluxus", L"fluxusz", L"scriptware", L"script-ware",
    L"arceusx", L"arceus x", L"arceus x neo",
    L"jjsploit", L"jj exploit", L"trigon", L"trigon evo",
    L"evon", L"evon executor", L"nihon", L"krampus",
    L"furkultra", L"furk ultra", L"dansploit", L"proxo",
    L"macsploit", L"roexec", L"sirhurt", L"cocoexploit", L"coco exploit",
    L"zorara", L"cefacode", L"vegax", L"solara", L"solara executor",
    L"delta executor", L"deltaexploit", L"delta exploit", L"delta x",
    L"xeno executor", L"xeno injector", L"xenoinjector",
    L"bunni executor", L"bunni exploit",
    L"codex executor", L"codex exploit",
    L"wave executor", L"wave exploit",
    L"velocity executor",
    L"lx63", L"alysse executor", L"alysse exploit",
    L"hydrogen executor", L"hydrogen exploit",
    L"electron executor", L"celex", L"celex v2",
    L"incognito executor", L"horizon external",
    L"luna executor", L"zenith executor", L"zenith executive",
    L"neutron executor", L"neutron exploit",
    L"wearedevs", L"easyexploits", L"kingexploits",
    L"bloxproducts", L"getcore.cc", L"robloxhax",
    L"scriptblox", L"infinite yield", L"dex explorer",
    L"extreme injector", L"celery executor", L"celery injector",
    L"rc7", L"proto smasher", L"calamari",
    L"coco z", L"valyse", L"nezur",
    L"seliware", L"oxygen u", L"oxygen-u", L"kiwi x", L"kiwix", L"comet executor",
    L"shadow executor", L"aspect executor", L"novaline", L"sigma executor", L"meteor executor",
    L"appleware", L"nexus executor", L"cryptic executor", L"phantom executor",
    L"eclipse executor", L"omega executor", L"ro-exec", L"krampus.gg",
    // Matcha / External / aimbot tools
    L"matcha.exe", L"matcha aimbot", L"matcha external", L"matcha esp", L"matcha cheat", L"matcha exploit",
    L"aimmy", L"aimmy.exe", L"aimmy-", L"aimblox", L"camlock", L"roblox camlock",
    L"matrixhub", L"matrix hub", L"matrix external",
    L"matrix executor", L"matrix exploit", L"matrix aimbot",
    L"oldui", L"newui", L"old ui", L"new ui",
    L"serotonin external", L"serotonin exploit", L"serotonin executor",
    L"thunder aim", L"thunderaim",
    L"da hood aimbot", L"da hood external", L"da hood script", L"dahood aimbot",
    L"rivals aimbot", L"rivals external", L"rivals esp",
    L"silent aim", L"silentaim", L"roblox aimbot", L"roblox esp hack",
    L"desync exploit", L"server-sided desync",
    L"triggerbot", L"roblox triggerbot",
    L"hitbox expander", L"hitbox exploit",
    L"match external", L"match exploit", L"match aimbot", // Re-added safe match strings
    // HWID spoofer names
    L"hwid-spoofer", L"hwid spoofer", L"easyhwid", L"qlitech",
    L"permanentspoofer", L"ruinspoofer", L"mac address changer", L"volumeid", L"hwid changer",
};

const std::vector<std::wstring> CHEAT_FILE_SIGNATURES = {
    // 100+ file signatures
    L"solara", L"fluxus", L"fluxusz", L"krnl", L"jjsploit",
    L"trigon", L"synapsex", L"synapsez", L"sirhurt",
    L"arceusx", L"evon", L"dansploit", L"roexec",
    L"nihon", L"krampus", L"furkultra", L"cocoexploit",
    L"zorara", L"cefacode", L"scriptware",
    L"deltaexecutor", L"xeno", L"xenoinjector",
    L"bunniexecutor",
    L"codexexecutor",
    L"waveexecutor",
    L"velocityexecutor",
    L"lx63", L"hydrogen", L"celex", L"alysse",
    L"luna executor", L"zenith executor", L"neutron executor", L"incognito executor", L"horizon external",
    L"oldui", L"newui", L"matrixhub", L"matrix external", L"matrix aimbot",
    L"serotonin", L"thunderaim",
    L"seliware", L"oxygen u", L"kiwi x", L"comet executor", L"shadow executor",
    L"appleware", L"nexus executor", L"cryptic executor", L"phantom executor",
    L"matcha.exe", L"matcha aimbot", L"matcha external", L"aimmy", L"camlock",
    L"da hood aimbot", L"rivals aimbot", L"silent aim",
    L"celeryinject", L"wpfui", L"celeryexecutor",
    // DLL injectors
    L"rbxinjector", L"luainjector", L"exploitapi",
    L"krnlss", L"wpfui", L"injector.exe", L"extreme injector",
    // Lua scripts
    L"autoexec", L"autoattach",
    // Original entries
    L"cheatengine", L"cheat engine", L"processhacker", L"process hacker",
    L"wearedevs",
    L"rc7", L"proto smasher",
    L"valyse", L"nezur",
    L"hwid-spoofer", L"hwid spoofer", L"easyhwid",
    L"kdmapper", L"pcihide", L"serial changer",
    L"maofficialvape",
};

// Folder signatures ??? directories that indicate cheat tools
const std::vector<std::wstring> FOLDER_SIGS = {
    L"autoexec", L"scriptblox", L"robloxhax",
    L"exploitscripts", L"luainjector", L"rbxinjector",
    L"dllinjector", L"wpfui_solara",
    L"fluxus_data", L"synapse_data", L"krnl_data", L"sirhurt_data",
    L"workspace\\autoexec",
    L"delta executor", L"xeno executor", L"bunni executor",
    L"codex executor", L"wave executor", L"velocity executor",
    L"serotonin", L"thunderaim", L"matcha", L"matcha aimbot", L"aimmy",
    L"wearedevs", L"easyexploits", L"matrixhub",
    L"oldui", L"newui", L"oxygen u", L"kiwi x",
    L"appleware", L"krampus", L"ro-exec", L"celery",
};

// Android emulator detection
const std::vector<std::wstring> EMULATOR_FILES = {
    L"mumuplayer.exe", L"mumumanager.exe",
    L"bluestacks.exe", L"bsconsole.exe",
    L"ldplayer.exe", L"ldconsole.exe",
    L"memuplay.exe", L"memuhyperv.exe",
    L"nox.exe", L"noxplayer.exe", L"gameloop.exe",
};

const std::vector<std::wstring> EMULATOR_FOLDERS = {
    L"mumuplayer", L"bluestacks", L"bluestacks_nxt",
    L"ldplayer", L"memuplay", L"noxplayer", L"gameloop",
};

// Browser history ??? cheat-related URL fragments to search for
const std::vector<std::string> BROWSER_CHEAT_URLS = {
    "wearedevs.net", "easyexploits.com", "kingexploits.com",
    "delta-executor.com", "delta-executor.org", "delta-exploits.org",
    "deltaexecutor.ai", "deltadevs.net", "getcore.cc",
    "bloxproducts.com", "fluxteam.net",
    "krnl.place", "krnl.rocks", "solara.dev",
    "whatexpsare.online", "arceusx.net",
    "hydrogenexecutor.com", "rblxscripts.net",
    "cheater.fun", "robloxscripts.com", "scriptblox.com",
    "matrixhubs.shop", "matrixhub.xyz",
    "keybypass.net", "linkvertise.com",
    "v3rmillion.net", "robloxhax.com", "pastebin.com",
    "discord.gg/solara", "discord.gg/krnl", "discord.gg/fluxus",
    "github.com/aimmy", "matcha.gg", "matcha-aimbot.com",
    "ro-exec.com", "krampus.gg", "krampus.net", "appleware.dev",
    "oxygenu.com", "kiwix.com", "celery.zip", "celeryexecutor",
    "synapsex.net", "synapse.to", "script-ware.com",
};

// Directories in AppData to SKIP during file scanning ??? these are known-safe
const std::vector<std::wstring> SAFE_APPDATA_DIRS = {
    L"node_modules", L".minecraft", L".fabric",
    L"opera software", L"opera gx stable",
    L"razer", L"razer synapse",
    L"overwolf", L"ow-electron",
    L"curseforge", L"lunarclient", L"lunar client",
    L"feather", L"steam", L"epic games",
    L"discord", L"slack", L"microsoft",
    L"google", L"mozilla", L"brave software",
    L"nuget", L"npm", L"yarn",
    L"vscode", L"code", L"jetbrains",
    L"ghidra", L"ida", L"wireshark",
    L"redact", L"patchright", L"playwright", L"puppeteer",
    // Browser & app caches (massive, never contain cheats)
    L"cache", L"code cache", L"gpucache", L"shadercache",
    L"cachestorage", L"service worker",
    L"package cache", L"pip", L"npm-cache",
    L"packages", L"nuget", L"__pycache__",
    L".cache", L".gradle", L".cargo", L".rustup",
    L".npm", L".yarn", L".pnpm-store",
    // Apps that have huge folder trees
    L"spotify", L"telegram desktop", L"zoom",
    L"obs-studio", L"vlc", L"gimp",
    L"blender", L"unity", L"unreal engine",
    L"adobe", L"autodesk", L"figma",
    L"nvidia", L"amd", L"intel",
    L"windows", L"windowsapps",
    L"python", L"anaconda", L"miniconda",
    L"programs", L"crashdumps", L"diagnostics",
    L"logs", L"temp", L"d3dscache",
};

// Window class prefixes that are safe (framework classes, not cheat windows)
const std::vector<std::wstring> SAFE_WINDOW_PREFIXES = {
    L"electron_", L"chrome_", L"mozilla",
    L"gdkwindow", L"qt_", L"wx",
    L"avalonia", L"wpf", L"windows.ui",
};

// Known spoofer / cheat kernel driver service names
// EasyAntiCheat_EOS REMOVED ??? it is a legitimate anti-cheat driver
const std::vector<std::wstring> SPOOFER_DRIVERS = {
    L"physmem", L"dbk64", L"dbk32", L"KProcessHacker", L"KProcessHacker3",
    L"HW64", L"gdrv", L"WinRing0", L"WinRing0_1_2_0",
    L"cpuz141", L"AsrDrv106",
    L"NTIOLib_X64", L"DirectIo64", L"GIO",
    L"RTCore64", L"IOMAP64",
    L"EneTechIo64", L"MsIo64", L"WinIo",
    L"inpoutx64", L"kdmapper", L"capcom",
    L"AsrSetupDrv106", L"atszio64",
    L"phymemx64", L"superbmc",
};

const std::vector<std::wstring> CHEAT_DOMAINS = {
    L"wearedevs.net", L"krnl.place", L"krnl.ca", L"krnl.gg", L"krnl.rocks",
    L"synapsex.to", L"synapsex.com", L"x.synapse.to",
    L"fluxteam.net", L"scriptware.net", L"arceusx.com", L"arceusx.net",
    L"jjsploit.net", L"trigon.rip", L"evon.cc",
    L"valyse.xyz", L"nezur.com", L"solara.dev",
    L"delta.gg", L"getwave.gg",
    L"delta-executor.com", L"delta-executor.org", L"delta-exploits.org",
    L"deltaexecutor.ai", L"deltadevs.net",
    L"easyexploits.com", L"kingexploits.com",
    L"getcore.cc", L"bloxproducts.com",
    L"whatexpsare.online", L"hydrogenexecutor.com",
    L"rblxscripts.net", L"cheater.fun",
    L"robloxscripts.com", L"scriptblox.com",
    L"matrixhubs.shop", L"matrixhub.xyz",
    L"keybypass.net", L"linkvertise.com",
    L"v3rmillion.net", L"robloxhax.com",
};

// ============================================================================
// UTILITIES

std::wstring Lower(const std::wstring& w);
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

// ============================================================================

std::string WideToAnsi(const std::wstring& w) {
    if (w.empty()) return "";
    int s = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string r(s, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), &r[0], s, nullptr, nullptr);
    return r;
}

std::wstring AnsiToWide(const std::string& a) {
    if (a.empty()) return L"";
    int s = MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), nullptr, 0);
    std::wstring r(s, 0);
    MultiByteToWideChar(CP_UTF8, 0, a.c_str(), (int)a.size(), &r[0], s);
    return r;
}

std::wstring Lower(const std::wstring& w) {
    std::wstring r = w;
    std::transform(r.begin(), r.end(), r.begin(), towlower);
    return r;
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    char buf[64];
    struct tm local_tm;
    localtime_s(&local_tm, &now);
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &local_tm);
    return buf;
}

std::wstring GetExeDirectory() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring dir(path);
    size_t pos = dir.find_last_of(L"\\/");
    if (pos != std::wstring::npos) dir = dir.substr(0, pos);
    return dir;
}

std::wstring NtPathToDosPath(const std::wstring& ntPath) {
    // Strip \\?\ prefix if present
    if (ntPath.find(L"\\\\?\\") == 0) {
        return ntPath.substr(4);
    }
    // Try QueryDosDevice for each drive letter
    for (wchar_t drive = L'A'; drive <= L'Z'; drive++) {
        wchar_t devicePath[512];
        wchar_t dosDrive[] = {drive, L':', L'\0'};
        if (QueryDosDeviceW(dosDrive, devicePath, 512)) {
            std::wstring device(devicePath);
            if (ntPath.find(device) == 0) {
                return dosDrive + ntPath.substr(device.size());
            }
        }
    }
    return ntPath;
}

std::wstring NormalizeModulePath(const std::wstring& path) {
    std::wstring result = path;
    // Handle \\?\ prefix
    if (result.find(L"\\\\?\\") == 0) {
        result = result.substr(4);
    }
    // Handle \Device\HarddiskVolumeN\ paths
    if (result.find(L"\\Device\\") == 0) {
        result = NtPathToDosPath(result);
    }
    return result;
}

bool IsSystemPath(const std::wstring& filePath) {
    std::wstring lower = Lower(filePath);
    std::wstring normalized = Lower(NormalizeModulePath(filePath));

    // Standard Windows system directories
    if (normalized.find(L":\\windows\\system32\\") != std::wstring::npos) return true;
    if (normalized.find(L":\\windows\\syswow64\\") != std::wstring::npos) return true;
    if (normalized.find(L":\\windows\\winsxs\\") != std::wstring::npos) return true;
    if (normalized.find(L":\\windows\\systemapps\\") != std::wstring::npos) return true;
    if (normalized.find(L":\\windows\\assembly\\") != std::wstring::npos) return true;
    if (normalized.find(L":\\windows\\microsoft.net\\") != std::wstring::npos) return true;

    // Also check via GetSystemDirectoryW
    wchar_t sysDir[MAX_PATH];
    if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
        std::wstring sysPath = Lower(std::wstring(sysDir));
        if (normalized.find(sysPath) == 0) return true;
    }
    return false;
}

bool IsWhitelistedDLL(const std::wstring& dllName) {
    return WINDOWS_DLL_WHITELIST.count(Lower(dllName)) > 0;
}

std::string JsonEscape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:   out += c; break;
        }
    }
    return out;
}

// ============================================================================
// HARDWARE ID
// ============================================================================

std::string GetHardwareID() {
    std::string cpu, mobo, disk, mac;
    HKEY hKey;

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Hardware\\Description\\System\\CentralProcessor\\0", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t name[256]; DWORD size = sizeof(name);
        if (RegQueryValueExW(hKey, L"ProcessorNameString", nullptr, nullptr, (LPBYTE)name, &size) == ERROR_SUCCESS)
            cpu = WideToAnsi(name);
        RegCloseKey(hKey);
    }

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        wchar_t id[256]; DWORD size = sizeof(id);
        if (RegQueryValueExW(hKey, L"ProductId", nullptr, nullptr, (LPBYTE)id, &size) == ERROR_SUCCESS)
            mobo = WideToAnsi(id);
        RegCloseKey(hKey);
    }

    STORAGE_PROPERTY_QUERY spq;
    ZeroMemory(&spq, sizeof(spq));
    spq.PropertyId = StorageDeviceProperty;
    spq.QueryType = PropertyStandardQuery;
    HANDLE hDev = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDev != INVALID_HANDLE_VALUE) {
        DWORD br; BYTE buf[1024];
        if (DeviceIoControl(hDev, IOCTL_STORAGE_QUERY_PROPERTY, &spq, sizeof(spq), buf, sizeof(buf), &br, nullptr) && br > sizeof(STORAGE_DEVICE_DESCRIPTOR)) {
            STORAGE_DEVICE_DESCRIPTOR* d = (STORAGE_DEVICE_DESCRIPTOR*)buf;
            if (d->SerialNumberOffset > 0 && d->SerialNumberOffset < br) disk = std::string((char*)buf + d->SerialNumberOffset);
        }
        CloseHandle(hDev);
    }

    IP_ADAPTER_INFO info[16]; DWORD size = sizeof(info);
    if (GetAdaptersInfo(info, &size) == ERROR_SUCCESS) {
        PIP_ADAPTER_INFO a = info;
        while (a) {
            if (a->AddressLength == 6) {
                char m[18]; sprintf_s(m, "%02X:%02X:%02X:%02X:%02X:%02X",
                    a->Address[0], a->Address[1], a->Address[2], a->Address[3], a->Address[4], a->Address[5]);
                mac = m; break;
            }
            a = a->Next;
        }
    }

    std::string combined = cpu + mobo + disk + mac;
    unsigned long hash = 5381;
    for (char c : combined) hash = ((hash << 5) + hash) + c;
    char result[32]; sprintf_s(result, "%08X", hash);
    return result;
}

// ============================================================================
// 1. CRYPTOGRAPHIC VALIDATION ??? WinVerifyTrust + CertGetNameString
// ============================================================================

struct SignatureResult {
    bool isSigned;
    bool isTrusted;
    std::string publisher;
};

SignatureResult VerifyAuthenticode(const std::wstring& filePath) {
    SignatureResult result = {false, false, ""};

    // Normalize path before any check
    std::wstring normalizedPath = NormalizeModulePath(filePath);

    // Phase 1: Try WinVerifyTrust directly with embedded signature
    WINTRUST_FILE_INFO fileInfo = {0};
    fileInfo.cbStruct = sizeof(fileInfo);
    fileInfo.pcwszFilePath = normalizedPath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA trustData = {0};
    trustData.cbStruct = sizeof(trustData);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.pFile = &fileInfo;

    LONG status = WinVerifyTrust(nullptr, &action, &trustData);

    if (status == ERROR_SUCCESS) {
        result.isSigned = true;
        result.isTrusted = true;

        HCERTSTORE hStore = nullptr;
        HCRYPTMSG hMsg = nullptr;
        if (CryptQueryObject(CERT_QUERY_OBJECT_FILE, normalizedPath.c_str(),
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED, CERT_QUERY_FORMAT_FLAG_BINARY,
            0, nullptr, nullptr, nullptr, &hStore, &hMsg, nullptr))
        {
            DWORD signerInfoSize = 0;
            CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &signerInfoSize);
            if (signerInfoSize > 0) {
                std::vector<BYTE> signerBuf(signerInfoSize);
                if (CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, signerBuf.data(), &signerInfoSize)) {
                    PCMSG_SIGNER_INFO signerInfo = (PCMSG_SIGNER_INFO)signerBuf.data();
                    CERT_INFO certInfo = {0};
                    certInfo.Issuer = signerInfo->Issuer;
                    certInfo.SerialNumber = signerInfo->SerialNumber;

                    PCCERT_CONTEXT certCtx = CertFindCertificateInStore(
                        hStore, X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
                        0, CERT_FIND_SUBJECT_CERT, &certInfo, nullptr);

                    if (certCtx) {
                        char nameBuf[256];
                        CertGetNameStringA(certCtx, CERT_NAME_SIMPLE_DISPLAY_TYPE,
                            0, nullptr, nameBuf, sizeof(nameBuf));
                        result.publisher = nameBuf;
                        CertFreeCertificateContext(certCtx);
                    }
                }
            }
            if (hStore) CertCloseStore(hStore, 0);
            if (hMsg) CryptMsgClose(hMsg);
        }
        if (result.publisher.empty()) {
            result.publisher = "Microsoft Windows / Valid Authenticode";
        }
    }

    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &trustData);

    // Phase 2: Check Windows Security Catalog
    if (!result.isSigned) {
        HANDLE hFile = CreateFileW(normalizedPath.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            CatalogAPIs cat = LoadCatalogAPIs();
            if (cat.hWinTrust && cat.pAcquireContext && cat.pEnumCatalogFromHash && cat.pCalcHashFromFileHandle) {
                HCATINFO hCatAdmin = 0;
                if (cat.pAcquireContext(&hCatAdmin, nullptr, 0)) {
                    DWORD hashSize = 0;
                    cat.pCalcHashFromFileHandle(hFile, &hashSize, nullptr, 0);
                    if (hashSize > 0) {
                        std::vector<BYTE> hashVal(hashSize);
                        if (cat.pCalcHashFromFileHandle(hFile, &hashSize, hashVal.data(), 0)) {
                            HCATINFO hCatInfo = cat.pEnumCatalogFromHash(
                                hCatAdmin, hashVal.data(), hashSize, 0, nullptr);

                            if (hCatInfo) {
                                CATALOG_INFO catInfoStruct = {0};
                                catInfoStruct.cbStruct = sizeof(catInfoStruct);
                                if (cat.pCatalogInfoFromContext(hCatInfo, &catInfoStruct, 0)) {
                                    WINTRUST_CATALOG_INFO catData = {0};
                                    catData.cbStruct = sizeof(catData);
                                    catData.pcwszCatalogFilePath = catInfoStruct.wszCatalogFile;
                                    catData.pcwszMemberFilePath = normalizedPath.c_str();

                                    WINTRUST_DATA wtCatData = {0};
                                    wtCatData.cbStruct = sizeof(wtCatData);
                                    wtCatData.dwUIChoice = WTD_UI_NONE;
                                    wtCatData.fdwRevocationChecks = WTD_REVOKE_NONE;
                                    wtCatData.dwUnionChoice = WTD_CHOICE_CATALOG;
                                    wtCatData.pCatalog = &catData;
                                    wtCatData.dwStateAction = WTD_STATEACTION_VERIFY;

                                    LONG catStatus = WinVerifyTrust(nullptr, &action, &wtCatData);
                                    if (catStatus == ERROR_SUCCESS || catStatus == 0) {
                                        result.isSigned = true;
                                        result.isTrusted = true;
                                        result.publisher = "Microsoft Windows Catalog";
                                    }

                                    wtCatData.dwStateAction = WTD_STATEACTION_CLOSE;
                                    WinVerifyTrust(nullptr, &action, &wtCatData);
                                }
                                if (cat.pReleaseCatalogContext) cat.pReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
                            }
                        }
                    }
                    if (cat.pReleaseContext) cat.pReleaseContext(hCatAdmin, 0);
                }
                FreeLibrary(cat.hWinTrust);
            }
            CloseHandle(hFile);
        }
    }

    // Phase 3: System directory fallback ??? path is now normalized so comparison works
    if (!result.isSigned) {
        if (IsSystemPath(normalizedPath)) {
            result.isSigned = true;
            result.isTrusted = true;
            result.publisher = "Microsoft Windows OS Component";
        }
    }

    return result;
}

// ============================================================================
// 2. MANUAL-MAP DETECTION ??? Tightened: RWX + 64KB + PE header validation
// ============================================================================

struct ManualMapResult {
    bool detected;
    int suspiciousRegions;
    std::string evidence;
};

ManualMapResult DetectManualMapping(DWORD processId) {
    ManualMapResult result = {false, 0, ""};

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) return result;

    MEMORY_BASIC_INFORMATION mbi;
    LPVOID addr = 0;
    int confirmedRegions = 0;
    std::ostringstream evidence;

    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE) {
            // Only flag RWX or RW+COPY ??? R+X alone is normal JIT behavior
            bool isRWX = (mbi.Protect == PAGE_EXECUTE_READWRITE) ||
                         (mbi.Protect == PAGE_EXECUTE_WRITECOPY);

            // 64KB minimum ??? eliminates small JIT stubs, shellcode fragments
            if (isRWX && mbi.RegionSize >= 0x10000) {
                BYTE header[4] = {0};
                SIZE_T bytesRead = 0;
                if (ReadProcessMemory(hProcess, mbi.BaseAddress, header, 4, &bytesRead) && bytesRead >= 4) {
                    // Check MZ magic
                    if (header[0] == 0x4D && header[1] == 0x5A) {
                        // Read deeper ??? verify PE optional header magic at e_lfanew offset
                        BYTE dosHeader[64] = {0};
                        if (ReadProcessMemory(hProcess, mbi.BaseAddress, dosHeader, 64, &bytesRead) && bytesRead >= 64) {
                            DWORD peOffset = *(DWORD*)(dosHeader + 0x3C);
                            if (peOffset > 0 && peOffset < mbi.RegionSize - 4) {
                                BYTE peSignature[6] = {0};
                                if (ReadProcessMemory(hProcess, (LPVOID)((DWORD_PTR)mbi.BaseAddress + peOffset), peSignature, 6, &bytesRead) && bytesRead >= 6) {
                                    // Verify PE\0\0 signature
                                    if (peSignature[0] == 'P' && peSignature[1] == 'E' && peSignature[2] == 0 && peSignature[3] == 0) {
                                        // Valid PE in unbacked RWX memory ??? confirmed manual map
                                        confirmedRegions++;
                                        if (confirmedRegions <= 3) {
                                            evidence << "0x" << std::hex << (DWORD_PTR)mbi.BaseAddress
                                                     << " (" << std::dec << (mbi.RegionSize / 1024) << "KB RWX+PE)  ";
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
        if (addr > (LPVOID)0x7FFFFFFFFFFFFFFFULL) break;
    }

    CloseHandle(hProcess);

    if (confirmedRegions > 0) {
        result.detected = true;
        result.suspiciousRegions = confirmedRegions;
        result.evidence = std::to_string(confirmedRegions) + " PE images in unbacked RWX memory: " + evidence.str();
    }

    return result;
}

// ============================================================================
// 3. USN JOURNAL ??? Deleted File Tracking with Path Resolution
// ============================================================================

struct DeletedFile {
    std::wstring name;
    std::wstring fullPath;
    FILETIME timestamp;
};

std::vector<DeletedFile> ScanDeletedFiles(int lookbackHours) {
    std::vector<DeletedFile> deleted;

    HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE) return deleted;

    USN_JOURNAL_DATA journalData = {0};
    DWORD bytesReturned;
    if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                         &journalData, sizeof(journalData), &bytesReturned, nullptr)) {
        CloseHandle(hVol);
        return deleted;
    }

    FILETIME now; GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER uiNow;
    uiNow.LowPart = now.dwLowDateTime;
    uiNow.HighPart = now.dwHighDateTime;
    ULONGLONG threshold = (ULONGLONG)lookbackHours * 3600 * 10000000ULL;
    USN startUsn = (uiNow.QuadPart > threshold) ?
        (USN)((uiNow.QuadPart - threshold) / 10000000ULL) : 0;

    READ_USN_JOURNAL_DATA readData = {0};
    readData.StartUsn = startUsn;
    readData.ReasonMask = USN_REASON_FILE_DELETE;
    readData.UsnJournalID = journalData.UsnJournalID;

    char buffer[65536];
    DWORD bytesRead;

    while (DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData),
                           buffer, sizeof(buffer), &bytesRead, nullptr) && bytesRead > sizeof(USN))
    {
        USN nextUsn = *(USN*)buffer;
        if (nextUsn == 0) break;

        PUSN_RECORD record = (PUSN_RECORD)(buffer + sizeof(USN));
        while ((BYTE*)record < (BYTE*)buffer + bytesRead) {
            if (record->Reason & USN_REASON_FILE_DELETE) {
                DeletedFile df;
                df.name.assign(record->FileName, record->FileNameLength / sizeof(WCHAR));
                df.timestamp = *(FILETIME*)&record->TimeStamp;

                FILE_ID_DESCRIPTOR parentDesc = {0};
                parentDesc.dwSize = sizeof(parentDesc);
                parentDesc.Type = FileIdType;
                parentDesc.FileId.QuadPart = record->ParentFileReferenceNumber;

                HANDLE hParent = OpenFileById(hVol, &parentDesc, GENERIC_READ,
                                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                                              nullptr, FILE_FLAG_BACKUP_SEMANTICS);
                if (hParent != INVALID_HANDLE_VALUE) {
                    wchar_t fullPath[1024];
                    DWORD pathLen = GetFinalPathNameByHandleW(hParent, fullPath, 1024, FILE_NAME_NORMALIZED);
                    if (pathLen > 0 && pathLen < 1024) {
                        df.fullPath = NormalizeModulePath(std::wstring(fullPath)) + L"\\" + df.name;
                    }
                    CloseHandle(hParent);
                }

                deleted.push_back(df);
            }

            record = (PUSN_RECORD)((BYTE*)record + record->RecordLength);
        }
        readData.StartUsn = nextUsn;
    }

    CloseHandle(hVol);
    return deleted;
}

// ============================================================================
// 4. BAM REGISTRY ??? Execution History Forensics
// ============================================================================

struct BamEntry {
    std::wstring ntPath;
    std::wstring dosPath;
    FILETIME executionTime;
};

std::vector<BamEntry> ParseBamRegistry() {
    std::vector<BamEntry> entries;

    HKEY hBam;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        0, KEY_READ, &hBam) != ERROR_SUCCESS)
    {
        return entries;
    }

    DWORD sidIndex = 0;
    wchar_t sidBuf[256]; DWORD sidSize;
    while (true) {
        sidSize = sizeof(sidBuf) / sizeof(wchar_t);
        if (RegEnumKeyExW(hBam, sidIndex, sidBuf, &sidSize,
                          nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

        HKEY hUser;
        if (RegOpenKeyExW(hBam, sidBuf, 0, KEY_READ, &hUser) == ERROR_SUCCESS) {
            DWORD vIndex = 0;
            wchar_t valName[2048]; DWORD valNameSize;
            BYTE data[8192]; DWORD dataSize; DWORD type;

            while (true) {
                valNameSize = sizeof(valName) / sizeof(wchar_t);
                dataSize = sizeof(data);
                if (RegEnumValueW(hUser, vIndex, valName, &valNameSize,
                                  nullptr, &type, data, &dataSize) != ERROR_SUCCESS) break;

                if (type == REG_BINARY && dataSize >= 8) {
                    BamEntry entry;
                    entry.ntPath = valName;
                    memcpy(&entry.executionTime, data, sizeof(FILETIME));
                    entry.dosPath = NtPathToDosPath(entry.ntPath);
                    entries.push_back(entry);
                }
                vIndex++;
            }
            RegCloseKey(hUser);
        }
        sidIndex++;
    }

    RegCloseKey(hBam);
    return entries;
}

// ============================================================================
// 5. CHEAT DETECTION ENGINE ??? Rebalanced, expanded, hardened
// ============================================================================

struct Finding {
    std::string category;
    std::string description;
    int confidence;
    std::string evidence;
};

struct CheatResult {
    std::vector<Finding> findings;
    int score;
    std::string verdict;
};

bool MatchesCheatSignature(const std::wstring& name) {
    std::wstring lower = Lower(name);
    for (const auto& sig : CHEAT_SIGNATURES) {
        if (lower.find(Lower(sig)) != std::wstring::npos) return true;
    }
    return false;
}

bool MatchesCheatFileSignature(const std::wstring& filename) {
    std::wstring lower = Lower(filename);
    for (const auto& sig : CHEAT_FILE_SIGNATURES) {
        if (lower.find(Lower(sig)) != std::wstring::npos) return true;
    }
    return false;
}

bool IsInSafeDirectory(const std::wstring& fullPath) {
    std::wstring lower = Lower(fullPath);
    for (const auto& safe : SAFE_APPDATA_DIRS) {
        if (lower.find(L"\\" + Lower(safe) + L"\\") != std::wstring::npos) return true;
    }
    return false;
}

bool IsSafeWindowClass(const std::wstring& className) {
    std::wstring lower = Lower(className);
    for (const auto& prefix : SAFE_WINDOW_PREFIXES) {
        if (lower.find(Lower(prefix)) == 0) return true;
    }
    return false;
}

// Get age category string for a FILETIME
std::string GetFileAgeCategory(const FILETIME& ft) {
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER uiNow, uiTarget;
    uiNow.LowPart = now.dwLowDateTime;
    uiNow.HighPart = now.dwHighDateTime;
    uiTarget.LowPart = ft.dwLowDateTime;
    uiTarget.HighPart = ft.dwHighDateTime;
    
    if (uiNow.QuadPart < uiTarget.QuadPart) return "[Unknown Age]";
    
    ULONGLONG diffSeconds = (uiNow.QuadPart - uiTarget.QuadPart) / 10000000ULL;
    ULONGLONG days = diffSeconds / 86400;
    
    if (days <= 7) return "[< 1 Week]";
    if (days <= 14) return "[< 2 Weeks]";
    if (days <= 21) return "[< 3 Weeks]";
    if (days <= 31) return "[< 1 Month]";
    return "[> 1 Month]";
}

std::string GetPathAgeCategory(const std::filesystem::path& path) {
    try {
        auto ftime = std::filesystem::last_write_time(path);
        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(
            ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
        auto now = std::chrono::system_clock::now();
        auto diff = std::chrono::duration_cast<std::chrono::hours>(now - sctp).count();
        
        int days = diff / 24;
        if (days <= 7) return "[< 1 Week]";
        if (days <= 14) return "[< 2 Weeks]";
        if (days <= 21) return "[< 3 Weeks]";
        if (days <= 31) return "[< 1 Month]";
        return "[> 1 Month]";
    } catch (...) {
        return "[Unknown Age]";
    }
}

// Format FILETIME to readable string
std::string FileTimeToString(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[64];
    sprintf_s(buf, "%04d-%02d-%02d %02d:%02d:%02d",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

// Draw a smooth loading bar ??? animates from last position to current
int g_lastProgress = 0;
void UpdateProgress(int step, int totalSteps) {
    int barWidth = 40;
    int targetPercent = int(float(step) / totalSteps * 100.0f);
    
    // Animate from last position to current position
    for (int pct = g_lastProgress + 1; pct <= targetPercent; ++pct) {
        int pos = barWidth * pct / 100;
        std::cout << "\r    [+] Scanning: [";
        for (int i = 0; i < barWidth; ++i) {
            if (i < pos) std::cout << "#";
            else std::cout << " ";
        }
        std::cout << "] " << pct << "%";
        std::cout.flush();
    }
    g_lastProgress = targetPercent;
}

std::string GetBroadCategory(const Finding& f);

CheatResult FullScan() {
    CheatResult r;
    r.score = 0;

    // Category score accumulators for capping
    int unsignedDllTotal = 0;

    UpdateProgress(1, 31);

    // ========================================================================
    // PHASE 1: Process Scan ??? Check running processes against cheat signatures
    // ========================================================================
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (MatchesCheatSignature(pe.szExeFile)) {
                    r.findings.push_back({
                        "PROCESS",
                        WideToAnsi(pe.szExeFile),
                        100,
                        "PID: " + std::to_string(pe.th32ProcessID)
                    });
                    r.score += 50;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    UpdateProgress(2, 31);

    // ========================================================================
    // PHASE 2: Roblox Module Inspection ??? Authenticode + Path + Memory
    // ========================================================================
    DWORD robloxPid = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring exeName = Lower(pe.szExeFile);
                if (exeName == L"robloxplayerbeta.exe" || exeName == L"robloxplayerlauncher.exe" || exeName.find(L"roblox") != std::wstring::npos) {
                    robloxPid = pe.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }

    if (robloxPid > 0) {


        HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, robloxPid);
        if (modSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me; me.dwSize = sizeof(me);
            if (Module32FirstW(modSnap, &me)) {
                do {
                    std::wstring moduleName = me.szModule;
                    std::wstring modulePath = NormalizeModulePath(me.szExePath);

                    // Skip whitelisted Windows DLLs ??? they are not cheats
                    if (IsWhitelistedDLL(moduleName)) continue;

                    // Skip if it's clearly a system path
                    if (IsSystemPath(modulePath)) continue;

                    // Check 1: Known cheat signature in DLL name
                    if (MatchesCheatSignature(moduleName)) {
                        r.findings.push_back({
                            "DLL_INJECTION",
                            WideToAnsi(moduleName),
                            100,
                            WideToAnsi(modulePath)
                        });
                        r.score += 60;
                        continue;
                    }

                    // Check 2: Authenticode verification for non-system, non-whitelisted DLLs
                    SignatureResult sig = VerifyAuthenticode(modulePath);
                    if (!sig.isSigned) {
                        // Non-system, non-whitelisted, unsigned ??? this is worth noting
                        r.findings.push_back({
                            "UNSIGNED_DLL",
                            WideToAnsi(moduleName),
                            35,
                            "Path: " + WideToAnsi(modulePath)
                        });
                        unsignedDllTotal += 3;
                    } else if (!sig.isTrusted) {
                        r.findings.push_back({
                            "UNTRUSTED_SIGNER",
                            WideToAnsi(moduleName),
                            50,
                            "Signed by: " + sig.publisher
                        });
                        r.score += 15;
                    }
                } while (Module32NextW(modSnap, &me));
            }
            CloseHandle(modSnap);
        }

        // Manual-map detection

        ManualMapResult mmResult = DetectManualMapping(robloxPid);
        if (mmResult.detected) {
            r.findings.push_back({
                "MANUAL_MAPPING",
                "PE images in unbacked RWX memory inside Roblox",
                90,
                mmResult.evidence
            });
            r.score += 35;
        }
    } else {
    }

    // Apply capped unsigned DLL score
    r.score += (std::min)(unsignedDllTotal, MAX_UNSIGNED_DLL_SCORE);

    UpdateProgress(3, 31);

    // ========================================================================
    // PHASE 3: USN Journal ??? Deleted Cheat Files
    // ========================================================================
    {
        std::vector<DeletedFile> deleted = ScanDeletedFiles(USN_LOOKBACK_HOURS);
        for (const auto& df : deleted) {
            if (MatchesCheatSignature(df.name)) {
                r.findings.push_back({
                    "DELETED_FILE",
                    WideToAnsi(df.name),
                    90,
                    "Path: " + WideToAnsi(df.fullPath) + " | Deleted: " + FileTimeToString(df.timestamp)
                });
                r.score += 30;
            }
        }
    }

    UpdateProgress(4, 31);

    // ========================================================================
    // PHASE 4: BAM Registry ??? Execution History
    // ========================================================================
    {
        std::vector<BamEntry> bamEntries = ParseBamRegistry();
        for (const auto& entry : bamEntries) {
            if (MatchesCheatSignature(entry.dosPath)) {
                r.findings.push_back({
                    "BAM_EXECUTION",
                    WideToAnsi(entry.dosPath),
                    95,
                    GetFileAgeCategory(entry.executionTime) + " Last executed: " + FileTimeToString(entry.executionTime)
                });
                r.score += 40;
            }
        }
    }

    UpdateProgress(5, 31);

    // ========================================================================
    // PHASE 5: Prefetch ??? Execution Artifacts
    // ========================================================================
    try {
        for (const auto& e : std::filesystem::directory_iterator(L"C:\\Windows\\Prefetch")) {
            if (!e.is_regular_file()) continue;

            std::wstring fn = e.path().filename().wstring();
            if (MatchesCheatSignature(fn)) {
                r.findings.push_back({
                    "PREFETCH",
                    WideToAnsi(fn),
                    80,
                    GetPathAgeCategory(e.path()) + " Prefetch file confirms execution"
                });
                r.score += 20;
            }
        }
    } catch (...) {}

    UpdateProgress(6, 31);

    // ========================================================================
    // PHASE 6: HWID Spoofer Registry Artifacts
    // ========================================================================
    {
        // Check SMBIOS override in mssmbios service data
        HKEY hSmbios;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Services\\mssmbios\\Data",
            0, KEY_READ, &hSmbios) == ERROR_SUCCESS)
        {
            // Check if SMBiosData value has been modified ??? spoofers write custom SMBIOS tables here
            DWORD dataSize = 0;
            if (RegQueryValueExW(hSmbios, L"AcpiData", nullptr, nullptr, nullptr, &dataSize) == ERROR_SUCCESS) {
                // Check if the original data and current data differ ??? presence of custom data key is notable
                DWORD smbiosSize = 0;
                if (RegQueryValueExW(hSmbios, L"SMBiosData", nullptr, nullptr, nullptr, &smbiosSize) == ERROR_SUCCESS) {
                    // Both keys present and readable ??? check for known spoofer artifacts
                    // The mere existence of the AcpiData key alongside modified SMBiosData is not enough for a finding
                    // but we can check for zero-length or suspiciously small SMBIOS data
                    if (smbiosSize < 64) {
                        r.findings.push_back({
                            "HWID_SPOOFER",
                            "Abnormally small SMBIOS table (possible spoofer override)",
                            70,
                            "SMBiosData size: " + std::to_string(smbiosSize) + " bytes"
                        });
                        r.score += 30;
                    }
                }
            }
            RegCloseKey(hSmbios);
        }

        // Check for known spoofer/cheat kernel drivers in Services registry
        for (const auto& driverName : SPOOFER_DRIVERS) {
            std::wstring keyPath = L"SYSTEM\\CurrentControlSet\\Services\\" + driverName;
            HKEY hDriver;
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hDriver) == ERROR_SUCCESS) {
                r.findings.push_back({
                    "CHEAT_DRIVER",
                    WideToAnsi(driverName),
                    95,
                    "Kernel driver service registered: " + WideToAnsi(keyPath)
                });
                r.score += 50;
                RegCloseKey(hDriver);
            }
        }

        // Check for MAC address spoof via registry
        HKEY hNetClass;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}",
            0, KEY_READ, &hNetClass) == ERROR_SUCCESS)
        {
            DWORD subkeyIdx = 0;
            wchar_t subkey[256]; DWORD subkeySize;
            while (true) {
                subkeySize = sizeof(subkey) / sizeof(wchar_t);
                if (RegEnumKeyExW(hNetClass, subkeyIdx, subkey, &subkeySize,
                                  nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;

                HKEY hNic;
                if (RegOpenKeyExW(hNetClass, subkey, 0, KEY_READ, &hNic) == ERROR_SUCCESS) {
                    wchar_t macOverride[64]; DWORD macSize = sizeof(macOverride);
                    if (RegQueryValueExW(hNic, L"NetworkAddress", nullptr, nullptr,
                                         (LPBYTE)macOverride, &macSize) == ERROR_SUCCESS) {
                        r.findings.push_back({
                            "MAC_SPOOF",
                            "NetworkAddress override on NIC adapter",
                            85,
                            "Override value: " + WideToAnsi(macOverride)
                        });
                        r.score += 35;
                    }
                    RegCloseKey(hNic);
                }
                subkeyIdx++;
            }
            RegCloseKey(hNetClass);
        }
    }

    UpdateProgress(7, 31);

    // ========================================================================
    // PHASE 7: Window Title / Class Scan
    // ========================================================================
    {
        struct WindowScanData {
            std::vector<Finding>* findings;
            int* score;
        };
        WindowScanData wsd = {&r.findings, &r.score};

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            auto* data = reinterpret_cast<WindowScanData*>(lParam);
            wchar_t title[512] = {0};
            wchar_t className[256] = {0};
            GetWindowTextW(hwnd, title, 512);
            GetClassNameW(hwnd, className, 256);

            std::wstring titleStr(title);
            std::wstring classStr(className);

            // Skip known-safe framework window classes (Electron, Chrome, Qt, etc.)
            if (IsSafeWindowClass(classStr)) return TRUE;

            if (!titleStr.empty() && MatchesCheatSignature(titleStr)) {
                data->findings->push_back({
                    "WINDOW_TITLE",
                    WideToAnsi(titleStr),
                    75,
                    "Class: " + WideToAnsi(classStr)
                });
                *(data->score) += 25;
            }
            if (!classStr.empty() && MatchesCheatSignature(classStr)) {
                data->findings->push_back({
                    "WINDOW_CLASS",
                    WideToAnsi(classStr),
                    70,
                    "Title: " + WideToAnsi(titleStr)
                });
                *(data->score) += 20;
            }
            return TRUE;
        }, (LPARAM)&wsd);
    }

    UpdateProgress(8, 31);

    // ========================================================================
    // PHASE 8: Temp / AppData Injector Remnant Scan
    // ========================================================================
    {
        std::vector<std::wstring> scanPaths;

        wchar_t tempPath[MAX_PATH];
        if (GetTempPathW(MAX_PATH, tempPath)) scanPaths.push_back(tempPath);

        wchar_t appdataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appdataPath))) scanPaths.push_back(appdataPath);
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appdataPath))) scanPaths.push_back(appdataPath);

        // Scan the Downloads folder since users often leave cheat zips/exes there
        wchar_t profilePath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profilePath))) {
            scanPaths.push_back(std::wstring(profilePath) + L"\\Downloads");
            scanPaths.push_back(std::wstring(profilePath) + L"\\Desktop");
        }

        const int MAX_DEPTH = 3; // Cheats are never buried 15 dirs deep

        for (const auto& scanDir : scanPaths) {
            try {
                // Manual BFS with depth limit instead of recursive_directory_iterator
                std::vector<std::pair<std::wstring, int>> dirQueue;
                dirQueue.push_back({scanDir, 0});

                while (!dirQueue.empty()) {
                    auto [currentDir, depth] = dirQueue.back();
                    dirQueue.pop_back();

                    if (depth > MAX_DEPTH) continue;

                    try {
                        for (const auto& entry : std::filesystem::directory_iterator(
                            currentDir, std::filesystem::directory_options::skip_permission_denied))
                        {
                            if (entry.is_directory() && depth < MAX_DEPTH) {
                                std::wstring dirName = entry.path().filename().wstring();
                                // Skip safe directories
                                if (!IsInSafeDirectory(entry.path().wstring())) {
                                    dirQueue.push_back({entry.path().wstring(), depth + 1});
                                }
                                continue;
                            }

                            if (!entry.is_regular_file()) continue;

                            std::wstring fullPath = entry.path().wstring();
                            std::wstring filename = entry.path().filename().wstring();
                            std::wstring ext = Lower(entry.path().extension().wstring());

                            // Only scan executable file types
                            bool isExecutable = (ext == L".exe" || ext == L".dll" || ext == L".sys" || ext == L".scr" || ext == L".bat" || ext == L".cmd" || ext == L".ps1");
                            if (!isExecutable) continue;

                            if (MatchesCheatFileSignature(filename)) {
                                r.findings.push_back({
                                    "INJECTOR_REMNANT",
                                    WideToAnsi(filename),
                                    85,
                                    "Path: " + WideToAnsi(fullPath)
                                });
                                r.score += 30;
                            }

                            // Check for suspiciously named DLLs in random temp subdirectories
                            if ((ext == L".dll" || ext == L".exe") && entry.file_size() > 4096 && entry.file_size() < 50 * 1024 * 1024) {
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
                            }
                        }
                    } catch (...) {}
                }
            } catch (...) {}
        }
    }


    // ========================================================================
    // PHASE 9: Active Kernel Driver Enumeration
    // ========================================================================
    {
        LPVOID drivers[1024];
        DWORD cbNeeded;
        if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
            int driverCount = cbNeeded / sizeof(LPVOID);
            for (int i = 0; i < driverCount; i++) {
                wchar_t driverName[MAX_PATH];
                if (GetDeviceDriverBaseNameW(drivers[i], driverName, MAX_PATH)) {
                    std::wstring name(driverName);
                    for (const auto& spoofer : SPOOFER_DRIVERS) {
                        if (Lower(name).find(Lower(spoofer)) != std::wstring::npos) {
                            r.findings.push_back({
                                "ACTIVE_CHEAT_DRIVER",
                                WideToAnsi(name),
                                100,
                                "Loaded in kernel ??? active right now"
                            });
                            r.score += 50;
                            break;
                        }
                    }
                }
            }
        }
    }

    UpdateProgress(9, 31);

    // ========================================================================
    // PHASE 10: MuiCache Registry ??? Windows logs every EXE ever opened
    // ========================================================================
    {
        HKEY hMui;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache",
            0, KEY_READ, &hMui) == ERROR_SUCCESS)
        {
            DWORD idx = 0;
            wchar_t valueName[2048]; DWORD nameSize;
            while (true) {
                nameSize = sizeof(valueName) / sizeof(wchar_t);
                if (RegEnumValueW(hMui, idx, valueName, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                std::wstring vn(valueName);
                if (MatchesCheatSignature(vn)) {
                    r.findings.push_back({
                        "MUICACHE",
                        WideToAnsi(vn),
                        80,
                        "[Unknown Age] Windows MuiCache - program was opened on this PC"
                    });
                    r.score += 25;
                }
                idx++;
            }
            RegCloseKey(hMui);
        }
    }

    UpdateProgress(10, 31);

    // ========================================================================
    // PHASE 11: AppCompat / Compatibility Assistant Registry
    // ========================================================================
    {
        HKEY hAc;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store",
            0, KEY_READ, &hAc) == ERROR_SUCCESS)
        {
            DWORD idx = 0;
            wchar_t valueName[2048]; DWORD nameSize;
            while (true) {
                nameSize = sizeof(valueName) / sizeof(wchar_t);
                if (RegEnumValueW(hAc, idx, valueName, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                std::wstring vn(valueName);
                if (MatchesCheatSignature(vn)) {
                    r.findings.push_back({
                        "APPCOMPAT",
                        WideToAnsi(vn),
                        85,
                        "[Unknown Age] AppCompat registry - program was executed"
                    });
                    r.score += 25;
                }
                idx++;
            }
            RegCloseKey(hAc);
        }
    }

    UpdateProgress(12, 31);

    // ========================================================================
    // PHASE 12: Uninstall Registry ??? Was a cheat ever installed?
    // ========================================================================
    {
        const wchar_t* uninstallKeys[] = {
            L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
            nullptr
        };
        HKEY roots[] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };

        for (int ri = 0; ri < 2; ri++) {
            HKEY hUn;
            if (RegOpenKeyExW(roots[ri], uninstallKeys[0], 0, KEY_READ, &hUn) == ERROR_SUCCESS) {
                DWORD subIdx = 0;
                wchar_t subkey[256]; DWORD subSize;
                while (true) {
                    subSize = sizeof(subkey) / sizeof(wchar_t);
                    if (RegEnumKeyExW(hUn, subIdx, subkey, &subSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                    std::wstring sk(subkey);
                    if (MatchesCheatSignature(sk)) {
                        r.findings.push_back({
                            "UNINSTALL_REGISTRY",
                            WideToAnsi(sk),
                            75,
                            "[Unknown Age] Uninstall registry - cheat was installed"
                        });
                        r.score += 20;
                    }
                    // Also check DisplayName inside subkey
                    HKEY hSub;
                    if (RegOpenKeyExW(hUn, subkey, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                        wchar_t displayName[512]; DWORD dnSize = sizeof(displayName);
                        if (RegQueryValueExW(hSub, L"DisplayName", nullptr, nullptr, (LPBYTE)displayName, &dnSize) == ERROR_SUCCESS) {
                            std::wstring dn(displayName);
                            if (MatchesCheatSignature(dn)) {
                                r.findings.push_back({
                                    "UNINSTALL_REGISTRY",
                                    WideToAnsi(dn),
                                    75,
                                    "[Unknown Age] Uninstall DisplayName matches cheat signature"
                                });
                                r.score += 20;
                            }
                        }
                        RegCloseKey(hSub);
                    }
                    subIdx++;
                }
                RegCloseKey(hUn);
            }
        }
    }

    UpdateProgress(13, 31);

    // ========================================================================
    // PHASE 13: UserAssist ??? ROT13-encoded execution history
    // ========================================================================
    {
        HKEY hUa;
        // UserAssist GUIDs that track program execution
        const wchar_t* uaGuids[] = {
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\\Count",
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}\\Count",
            nullptr
        };
        for (int gi = 0; uaGuids[gi]; gi++) {
            if (RegOpenKeyExW(HKEY_CURRENT_USER, uaGuids[gi], 0, KEY_READ, &hUa) == ERROR_SUCCESS) {
                DWORD idx = 0;
                wchar_t valueName[2048]; DWORD nameSize;
                BYTE data[1024]; DWORD dataSize; DWORD type;
                while (true) {
                    nameSize = sizeof(valueName) / sizeof(wchar_t);
                    dataSize = sizeof(data);
                    if (RegEnumValueW(hUa, idx, valueName, &nameSize, nullptr, &type, data, &dataSize) != ERROR_SUCCESS) break;
                    
                    std::string ageStr = "[Unknown Age]";
                    if (type == REG_BINARY && dataSize >= 72) {
                        FILETIME ft;
                        memcpy(&ft, data + 60, sizeof(FILETIME));
                        if (ft.dwHighDateTime != 0 || ft.dwLowDateTime != 0) {
                            ageStr = GetFileAgeCategory(ft);
                        }
                    }

                    // Decode ROT13
                    std::wstring decoded(valueName);
                    for (auto& ch : decoded) {
                        if ((ch >= L'a' && ch <= L'z')) ch = L'a' + ((ch - L'a' + 13) % 26);
                        else if ((ch >= L'A' && ch <= L'Z')) ch = L'A' + ((ch - L'A' + 13) % 26);
                    }
                    if (MatchesCheatSignature(decoded)) {
                        r.findings.push_back({
                            "USERASSIST",
                            WideToAnsi(decoded),
                            85,
                            ageStr + " UserAssist (ROT13 decoded) - program was launched"
                        });
                        r.score += 30;
                    }
                    idx++;
                }
                RegCloseKey(hUa);
            }
        }
    }

    UpdateProgress(14, 31);

    // ========================================================================
    // PHASE 14: DNS Cache ??? ipconfig /displaydns
    // ========================================================================
    {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"ipconfig /displaydns";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string dnsOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    dnsOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 3000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::string dnsLower = dnsOutput;
                std::transform(dnsLower.begin(), dnsLower.end(), dnsLower.begin(), ::tolower);
                for (const auto& domain : CHEAT_DOMAINS) {
                    std::string domStr = WideToAnsi(domain);
                    std::string domLower = domStr;
                    std::transform(domLower.begin(), domLower.end(), domLower.begin(), ::tolower);
                    if (dnsLower.find(domLower) != std::string::npos) {
                        r.findings.push_back({
                            "DNS_CACHE",
                            domStr,
                            70,
                            "Cheat domain found in DNS cache"
                        });
                        r.score += 20;
                    }
                }
            } else {
                CloseHandle(hWrite);
                CloseHandle(hRead);
            }
        }
    }

    UpdateProgress(15, 31);

    // ========================================================================
    // PHASE 15: Scheduled Tasks ??? schtasks /query
    // ========================================================================
    {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"schtasks /query /fo LIST";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string taskOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    taskOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::wstring taskW = AnsiToWide(taskOutput);
                std::wstring taskLower = Lower(taskW);
                for (const auto& sig : CHEAT_SIGNATURES) {
                    if (taskLower.find(Lower(sig)) != std::wstring::npos) {
                        r.findings.push_back({
                            "SCHEDULED_TASK",
                            WideToAnsi(sig),
                            60,
                            "Cheat-related scheduled task found"
                        });
                        r.score += 15;
                    }
                }
            } else {
                CloseHandle(hWrite);
                CloseHandle(hRead);
            }
        }
    }

    UpdateProgress(16, 31);

    // ========================================================================
    // PHASE 16: Firewall Rules
    // ========================================================================
    {
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"netsh advfirewall firewall show rule name=all";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string fwOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    fwOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::wstring fwW = AnsiToWide(fwOutput);
                std::wstring fwLower = Lower(fwW);
                for (const auto& sig : CHEAT_SIGNATURES) {
                    if (fwLower.find(Lower(sig)) != std::wstring::npos) {
                        r.findings.push_back({
                            "FIREWALL_RULE",
                            WideToAnsi(sig),
                            55,
                            "Cheat-related firewall rule found"
                        });
                        r.score += 10;
                    }
                }
            } else {
                CloseHandle(hWrite);
                CloseHandle(hRead);
            }
        }
    }

    UpdateProgress(17, 31);

    // ========================================================================
    // PHASE 17: Browser History ??? Raw byte scan of browser DBs
    // Scans Chrome, Edge, Brave, Firefox, Opera for cheat site visits
    // Also scans WAL/journal files for deleted history
    // ========================================================================
    {
        wchar_t localAppData[MAX_PATH], appData[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
        SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData);

        // Chromium-based browsers (History file is SQLite)
        std::vector<std::wstring> chromiumPaths = {
            std::wstring(localAppData) + L"\\Google\\Chrome\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera GX Stable\\History",
            std::wstring(localAppData) + L"\\Opera Software\\Opera Stable\\History",
            std::wstring(localAppData) + L"\\Vivaldi\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Arc\\User Data\\Default\\History",
            std::wstring(localAppData) + L"\\Chromium\\User Data\\Default\\History",
        };

        // Also check WAL and journal files (contain deleted/uncommitted data)
        std::vector<std::wstring> allBrowserFiles;
        for (const auto& p : chromiumPaths) {
            allBrowserFiles.push_back(p);
            allBrowserFiles.push_back(p + L"-wal");
            allBrowserFiles.push_back(p + L"-journal");
        }

        // Firefox ??? find profiles
        std::wstring ffProfiles = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
        try {
            for (const auto& entry : std::filesystem::directory_iterator(ffProfiles)) {
                if (entry.is_directory()) {
                    std::wstring placesDb = entry.path().wstring() + L"\\places.sqlite";
                    allBrowserFiles.push_back(placesDb);
                    allBrowserFiles.push_back(placesDb + L"-wal");
                    allBrowserFiles.push_back(placesDb + L"-journal");
                }
            }
        } catch (...) {}

        for (const auto& dbPath : allBrowserFiles) {
            try {
                std::ifstream f(dbPath.c_str(), std::ios::binary);
                if (!f.is_open()) continue;

                // Read up to 50MB of the file
                std::string content;
                content.resize(50 * 1024 * 1024);
                f.read(&content[0], content.size());
                content.resize(f.gcount());
                f.close();

                std::string contentLower = content;
                std::transform(contentLower.begin(), contentLower.end(), contentLower.begin(), ::tolower);

                for (const auto& url : BROWSER_CHEAT_URLS) {
                    std::string urlLower = url;
                    std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
                    if (contentLower.find(urlLower) != std::string::npos) {
                        bool isWal = dbPath.find(L"-wal") != std::wstring::npos || dbPath.find(L"-journal") != std::wstring::npos;
                        r.findings.push_back({
                            isWal ? "DELETED_BROWSER_HISTORY" : "BROWSER_HISTORY",
                            url,
                            isWal ? 90 : 75,
                            (isWal ? "Deleted browser history contains: " : "Browser history contains: ") + WideToAnsi(dbPath)
                        });
                        r.score += isWal ? 30 : 20;
                    }
                }
            } catch (...) {}
        }
    }

    UpdateProgress(18, 31);

    // ========================================================================
    // PHASE 18: Recent Files ??? Windows Recent folder (.lnk files)
    // ========================================================================
    {
        wchar_t appData[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData);
        std::wstring recentDir = std::wstring(appData) + L"\\Microsoft\\Windows\\Recent";
        try {
            for (const auto& entry : std::filesystem::directory_iterator(recentDir)) {
                if (!entry.is_regular_file()) continue;
                std::wstring fn = entry.path().filename().wstring();
                if (MatchesCheatSignature(fn)) {
                    r.findings.push_back({
                        "RECENT_FILE",
                        WideToAnsi(fn),
                        70,
                        "Windows Recent folder ??? cheat shortcut found"
                    });
                    r.score += 15;
                }
            }
        } catch (...) {}
    }

    UpdateProgress(19, 31);

    // ========================================================================
    // PHASE 19: Emulator Detection ??? Android emulators for mobile cheats
    // ========================================================================
    {
        // Check running emulator processes
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    std::wstring exeName = Lower(pe.szExeFile);
                    for (const auto& emu : EMULATOR_FILES) {
                        if (exeName == Lower(emu)) {
                            r.findings.push_back({
                                "EMULATOR_PROCESS",
                                WideToAnsi(pe.szExeFile),
                                40,
                                "Android emulator running ??? PID: " + std::to_string(pe.th32ProcessID)
                            });
                            r.score += 10;
                            break;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        // Check emulator install directories
        wchar_t programFiles[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_PROGRAM_FILES, nullptr, 0, programFiles);
        for (const auto& emuDir : EMULATOR_FOLDERS) {
            std::wstring fullPath = std::wstring(programFiles) + L"\\" + emuDir;
            if (std::filesystem::exists(fullPath)) {
                r.findings.push_back({
                    "EMULATOR_INSTALLED",
                    WideToAnsi(emuDir),
                    35,
                    "Emulator directory found: " + WideToAnsi(fullPath)
                });
                r.score += 5;
            }
        }
    }

    UpdateProgress(20, 31);

    // ========================================================================
    // PHASE 21: VM / Sandbox Detection (Are they faking a clean PC?)
    // ========================================================================
    {
        std::vector<std::string> vmArtifacts = {
            "vmtoolsd.exe", "vboxtray.exe", "vboxservice.exe",
            "qemu-ga.exe", "joeboxserver.exe", "joeboxcontrol.exe"
        };
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    std::string exe = WideToAnsi(pe.szExeFile);
                    std::transform(exe.begin(), exe.end(), exe.begin(), ::tolower);
                    for (const auto& vm : vmArtifacts) {
                        if (exe == vm) {
                            r.findings.push_back({
                                "VIRTUAL_MACHINE",
                                vm,
                                90,
                                "Virtual Machine detected (used to fake clean PC)"
                            });
                            r.score += 25; // Don't ban just for VM, but flag highly suspicious
                            break;
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        // Check for VM hardware MAC address prefixes (OUI)
        ULONG outBufLen = 15000;
        PIP_ADAPTER_ADDRESSES pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
        if (GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pAddresses, &outBufLen) == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES curr = pAddresses;
            while (curr) {
                if (curr->PhysicalAddressLength == 6) {
                    BYTE* mac = curr->PhysicalAddress;
                    // VMware: 00:05:69, 00:0C:29, 00:1C:14, 00:50:56
                    // VirtualBox: 08:00:27
                    if ((mac[0] == 0x00 && mac[1] == 0x05 && mac[2] == 0x69) ||
                        (mac[0] == 0x00 && mac[1] == 0x0C && mac[2] == 0x29) ||
                        (mac[0] == 0x00 && mac[1] == 0x1C && mac[2] == 0x14) ||
                        (mac[0] == 0x00 && mac[1] == 0x50 && mac[2] == 0x56) ||
                        (mac[0] == 0x08 && mac[1] == 0x00 && mac[2] == 0x27)) 
                    {
                        r.findings.push_back({
                            "VIRTUAL_MACHINE_MAC",
                            "VM Network Adapter",
                            95,
                            "Virtual Machine network adapter detected"
                        });
                        r.score += 20;
                    }
                }
                curr = curr->Next;
            }
        }
        free(pAddresses);
    }
    
    UpdateProgress(21, 31);

    // ========================================================================
    // PHASE 22: Remote Desktop Detection (Is someone else doing the PC check?)
    // ========================================================================
    {
        std::vector<std::string> rdps = {
            "teamviewer.exe", "teamviewer_service.exe", 
            "tv_w32.exe", "parsecd.exe", "rustdesk.exe", "supremo.exe"
        };
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    std::string exe = WideToAnsi(pe.szExeFile);
                    std::transform(exe.begin(), exe.end(), exe.begin(), ::tolower);
                    for (const auto& rdp : rdps) {
                        if (exe == rdp) {
                            r.findings.push_back({
                                "REMOTE_DESKTOP_TOOL",
                                rdp,
                                80,
                                "Remote Desktop software running (potential fake PC check)"
                            });
                            r.score += 15;
                            break;
                        }
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
    }
    
    UpdateProgress(22, 31);

    // ========================================================================
    // PHASE 20: Folder Signature Scan ??? cheat-related directories
    // ========================================================================
    {
        std::vector<std::wstring> scanRoots;
        wchar_t appDataPath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appDataPath))) scanRoots.push_back(appDataPath);
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, appDataPath))) scanRoots.push_back(appDataPath);

        wchar_t profilePath[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, 0, profilePath))) {
            scanRoots.push_back(std::wstring(profilePath) + L"\\Downloads");
            scanRoots.push_back(std::wstring(profilePath) + L"\\Desktop");
        }

        for (const auto& root : scanRoots) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(root)) {
                    if (!entry.is_directory()) continue;
                    std::wstring dirName = Lower(entry.path().filename().wstring());
                    for (const auto& sig : FOLDER_SIGS) {
                        if (dirName.find(Lower(sig)) != std::wstring::npos) {
                            r.findings.push_back({
                                "CHEAT_FOLDER",
                                WideToAnsi(entry.path().filename().wstring()),
                                65,
                                "Cheat directory found: " + WideToAnsi(entry.path().wstring())
                            });
                            r.score += 15;
                            break;
                        }
                    }
                }
            } catch (...) {}
        }
    }

    UpdateProgress(23, 31);

    // ========================================================================
    // PHASE 23: DMA Card Detection ??? FPGA/PCILeech/Screamer hardware
    // ========================================================================
    {
        // Check for loaded DMA-related kernel drivers via registry
        const wchar_t* dmaDrivers[] = {
            L"pcileech", L"fpga", L"rawaccess", L"dma_driver",
            L"leechcore", L"winio", L"directio", nullptr
        };
        HKEY hDrivers;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services", 0, KEY_READ, &hDrivers) == ERROR_SUCCESS) {
            DWORD idx = 0;
            wchar_t subKeyName[256];
            DWORD subKeySize;
            while (true) {
                subKeySize = sizeof(subKeyName) / sizeof(wchar_t);
                if (RegEnumKeyExW(hDrivers, idx, subKeyName, &subKeySize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                std::wstring driverLower = Lower(subKeyName);
                for (int i = 0; dmaDrivers[i]; i++) {
                    if (driverLower.find(dmaDrivers[i]) != std::wstring::npos) {
                        r.findings.push_back({
                            "DMA_CARD",
                            WideToAnsi(subKeyName),
                            90,
                            "DMA/FPGA hardware driver detected ??? possible hardware cheat device"
                        });
                        r.score += 40;
                        break;
                    }
                }
                idx++;
            }
            RegCloseKey(hDrivers);
        }

        // Check for DMA-related device names via SetupDi
        HANDLE hRead, hWrite;
        SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
        if (CreatePipe(&hRead, &hWrite, &sa, 0)) {
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si.hStdOutput = hWrite;
            si.hStdError = hWrite;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            wchar_t cmd[] = L"wmic path Win32_PnPEntity get Name /format:list";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string pnpOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    pnpOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::string pnpLower = pnpOutput;
                std::transform(pnpLower.begin(), pnpLower.end(), pnpLower.begin(), ::tolower);
                const char* dmaKeywords[] = {"fpga", "screamer", "pcileech", "squirrel", nullptr};
                for (int i = 0; dmaKeywords[i]; i++) {
                    if (pnpLower.find(dmaKeywords[i]) != std::string::npos) {
                        r.findings.push_back({
                            "DMA_CARD",
                            dmaKeywords[i],
                            90,
                            "DMA hardware device found in PnP device list"
                        });
                        r.score += 40;
                    }
                }
            } else {
                CloseHandle(hWrite);
                CloseHandle(hRead);
            }
        }
    }

    UpdateProgress(24, 31);

    // ========================================================================
    // PHASE 24: Dual-PC / Network Streaming Detection
    // NOTE: AnyDesk is WHITELISTED ??? PC checkers use it
    // ========================================================================
    {
        const wchar_t* streamProcs[] = {
            L"parsec.exe", L"parsecd.exe", L"moonlight.exe",
            L"sunshine.exe", L"steamlink.exe", L"steam_link.exe",
            L"rustdesk.exe", L"supremo.exe",
            nullptr
        };
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
            if (Process32FirstW(snap, &pe)) {
                do {
                    std::wstring exeName = Lower(pe.szExeFile);
                    for (int i = 0; streamProcs[i]; i++) {
                        if (exeName == Lower(streamProcs[i])) {
                            r.findings.push_back({
                                "DUAL_PC_STREAMING",
                                WideToAnsi(pe.szExeFile),
                                70,
                                "Remote streaming software running - possible dual-PC cheat setup"
                            });
                            r.score += 20;
                            break;
                        }
                    }
                } while (Process32NextW(snap, &pe));
            }
            CloseHandle(snap);
        }

        // Check for streaming ports via netstat
        HANDLE hRead2, hWrite2;
        SECURITY_ATTRIBUTES sa2 = { sizeof(sa2), nullptr, TRUE };
        if (CreatePipe(&hRead2, &hWrite2, &sa2, 0)) {
            STARTUPINFOW si2 = { sizeof(si2) };
            si2.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si2.hStdOutput = hWrite2;
            si2.hStdError = hWrite2;
            si2.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi2 = {0};
            wchar_t cmd2[] = L"netstat -an";
            if (CreateProcessW(nullptr, cmd2, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si2, &pi2)) {
                CloseHandle(hWrite2);
                std::string netOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead2, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    netOutput += buf;
                }
                CloseHandle(hRead2);
                WaitForSingleObject(pi2.hProcess, 5000);
                CloseHandle(pi2.hProcess);
                CloseHandle(pi2.hThread);

                // Check for Moonlight (47984-47989), Sunshine (47989-47990). Removed Parsec (8000) as it is too generic.
                const char* streamPorts[] = {":47984 ", ":47985 ", ":47986 ", ":47987 ", ":47988 ", ":47989 ", ":47990 ", nullptr};
                for (int i = 0; streamPorts[i]; i++) {
                    if (netOutput.find(streamPorts[i]) != std::string::npos) {
                        r.findings.push_back({
                            "STREAMING_PORT",
                            streamPorts[i],
                            30,
                            "Active streaming port detected (FYI only - not considered cheating)"
                        });
                        r.score += 0;
                        break;
                    }
                }
            } else {
                CloseHandle(hWrite2);
                CloseHandle(hRead2);
            }
        }
    }

    UpdateProgress(25, 31);

    // ========================================================================
    // PHASE 25: Timestomping Detection ??? manipulated file timestamps
    // ========================================================================
    {
        wchar_t tempPath[MAX_PATH], localAppData[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);

        std::vector<std::wstring> stompDirs = { tempPath, localAppData };
        for (const auto& dir : stompDirs) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                    if (!entry.is_regular_file()) continue;
                    std::wstring fn = Lower(entry.path().filename().wstring());
                    bool isCheatRelated = MatchesCheatSignature(fn);
                    if (!isCheatRelated) continue;

                    WIN32_FILE_ATTRIBUTE_DATA fad;
                    if (!GetFileAttributesExW(entry.path().c_str(), GetFileExInfoStandard, &fad)) continue;

                    ULARGE_INTEGER createTime, writeTime;
                    createTime.LowPart = fad.ftCreationTime.dwLowDateTime;
                    createTime.HighPart = fad.ftCreationTime.dwHighDateTime;
                    writeTime.LowPart = fad.ftLastWriteTime.dwLowDateTime;
                    writeTime.HighPart = fad.ftLastWriteTime.dwHighDateTime;

                    // CreationTime AFTER LastWriteTime = timestamps manipulated
                    if (createTime.QuadPart > writeTime.QuadPart && writeTime.QuadPart > 0) {
                        r.findings.push_back({
                            "TIMESTOMPING",
                            WideToAnsi(entry.path().filename().wstring()),
                            75,
                            "Timestomping detected ??? creation time is AFTER last write time"
                        });
                        r.score += 25;
                    }

                    // Suspiciously old creation time in temp (>1 year)
                    SYSTEMTIME now;
                    GetSystemTime(&now);
                    FILETIME ftNow;
                    SystemTimeToFileTime(&now, &ftNow);
                    ULARGE_INTEGER nowTime;
                    nowTime.LowPart = ftNow.dwLowDateTime;
                    nowTime.HighPart = ftNow.dwHighDateTime;
                    ULONGLONG oneYear = (ULONGLONG)365 * 24 * 60 * 60 * 10000000ULL;
                    if (createTime.QuadPart > 0 && (nowTime.QuadPart - createTime.QuadPart) > oneYear) {
                        std::wstring parentDir = Lower(entry.path().parent_path().wstring());
                        if (parentDir.find(L"temp") != std::wstring::npos) {
                            r.findings.push_back({
                                "TIMESTOMPING",
                                WideToAnsi(entry.path().filename().wstring()),
                                75,
                                "Suspiciously old file in Temp directory ??? possible timestamp manipulation"
                            });
                            r.score += 20;
                        }
                    }
                }
            } catch (...) {}
        }
    }

    UpdateProgress(26, 31);

    // ========================================================================
    // PHASE 26: Amcache Registry ??? execution history survives deletion
    // ========================================================================
    {
        HKEY hAmcache;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags", 0, KEY_READ, &hAmcache) == ERROR_SUCCESS) {
            // Enumerate subkeys recursively looking for file paths
            std::function<void(HKEY, int)> scanAmcache = [&](HKEY hKey, int depth) {
                if (depth > 3) return;
                DWORD idx = 0;
                wchar_t subKeyName[512]; DWORD subKeySize;
                while (true) {
                    subKeySize = sizeof(subKeyName) / sizeof(wchar_t);
                    if (RegEnumKeyExW(hKey, idx, subKeyName, &subKeySize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                    
                    std::wstring keyName(subKeyName);
                    if (MatchesCheatSignature(keyName)) {
                        r.findings.push_back({
                            "AMCACHE",
                            WideToAnsi(keyName),
                            85,
                            "Amcache/AppCompat - cheat execution recorded"
                        });
                        r.score += 30;
                    }

                    HKEY hSub;
                    if (RegOpenKeyExW(hKey, subKeyName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                        // Check values for file paths
                        DWORD valIdx = 0;
                        wchar_t valName[512]; DWORD valNameSize;
                        BYTE valData[2048]; DWORD valDataSize; DWORD valType;
                        while (true) {
                            valNameSize = sizeof(valName) / sizeof(wchar_t);
                            valDataSize = sizeof(valData);
                            if (RegEnumValueW(hSub, valIdx, valName, &valNameSize, nullptr, &valType, valData, &valDataSize) != ERROR_SUCCESS) break;
                            if (valType == REG_SZ || valType == REG_EXPAND_SZ) {
                                std::wstring valStr((wchar_t*)valData);
                                if (MatchesCheatSignature(valStr)) {
                                    r.findings.push_back({
                                        "AMCACHE",
                                        WideToAnsi(valStr),
                                        85,
                                        "Amcache value matches cheat signature"
                                    });
                                    r.score += 30;
                                }
                            }
                            valIdx++;
                        }
                        scanAmcache(hSub, depth + 1);
                        RegCloseKey(hSub);
                    }
                    idx++;
                }
            };
            scanAmcache(hAmcache, 0);
            RegCloseKey(hAmcache);
        }
    }

    UpdateProgress(27, 31);

    // ========================================================================
    // PHASE 27: SRUM Database ??? app execution history (30+ days)
    // ========================================================================
    {
        std::wstring srumPath = L"C:\\Windows\\System32\\sru\\SRUDB.dat";
        wchar_t tempDir[MAX_PATH];
        GetTempPathW(MAX_PATH, tempDir);
        std::wstring srumCopy = std::wstring(tempDir) + L"\\srudb_scan.dat";

        // Try to copy the locked SRUM database
        if (CopyFileW(srumPath.c_str(), srumCopy.c_str(), FALSE)) {
            try {
                std::ifstream f(WideToAnsi(srumCopy).c_str(), std::ios::binary);
                if (f.is_open()) {
                    std::string content;
                    content.resize(20 * 1024 * 1024); // 20MB max
                    f.read(&content[0], content.size());
                    content.resize(f.gcount());
                    f.close();

                    std::string contentLower = content;
                    std::transform(contentLower.begin(), contentLower.end(), contentLower.begin(), ::tolower);

                    for (const auto& sig : CHEAT_SIGNATURES) {
                        std::string sigAnsi = WideToAnsi(sig);
                        std::string sigLower = sigAnsi;
                        std::transform(sigLower.begin(), sigLower.end(), sigLower.begin(), ::tolower);
                        if (contentLower.find(sigLower) != std::string::npos) {
                            r.findings.push_back({
                                "SRUM_DATABASE",
                                sigAnsi,
                                80,
                                "SRUM database contains cheat execution history"
                            });
                            r.score += 25;
                        }
                    }
                }
            } catch (...) {}
            DeleteFileW(srumCopy.c_str());
        }
    }

    UpdateProgress(28, 31);

    // ========================================================================
    // PHASE 28: Recycle Bin Forensics ??? deleted cheat files
    // ========================================================================
    {
        try {
            std::wstring recycleBin = L"C:\\$Recycle.Bin";
            if (std::filesystem::exists(recycleBin)) {
                for (const auto& sidDir : std::filesystem::directory_iterator(recycleBin)) {
                    if (!sidDir.is_directory()) continue;
                    try {
                        for (const auto& entry : std::filesystem::directory_iterator(sidDir.path())) {
                            std::wstring fn = entry.path().filename().wstring();
                            // $I files contain metadata with original path
                            if (fn.size() > 2 && fn[0] == L'$' && fn[1] == L'I') {
                                try {
                                    std::ifstream iFile(entry.path(), std::ios::binary);
                                    if (!iFile.is_open()) continue;
                                    
                                    // $I file format: 8 bytes header, 8 bytes size, 8 bytes timestamp, then original path (wide string)
                                    char header[24];
                                    iFile.read(header, 24);
                                    if (iFile.gcount() < 24) { iFile.close(); continue; }
                                    
                                    // Read the original path (wide chars)
                                    std::vector<wchar_t> pathBuf(520);
                                    iFile.read((char*)pathBuf.data(), pathBuf.size() * sizeof(wchar_t));
                                    iFile.close();

                                    std::wstring origPath(pathBuf.data());
                                    if (MatchesCheatSignature(origPath)) {
                                        r.findings.push_back({
                                            "RECYCLE_BIN",
                                            WideToAnsi(origPath),
                                            80,
                                            "Deleted cheat file found in Recycle Bin"
                                        });
                                        r.score += 25;
                                    }
                                } catch (...) {}
                            }
                        }
                    } catch (...) {}
                }
            }
        } catch (...) {}
    }

    UpdateProgress(29, 31);

    // ========================================================================
    // PHASE 29: Volume Shadow Copies ??? evidence hiding
    // ========================================================================
    {
        HANDLE hRead3, hWrite3;
        SECURITY_ATTRIBUTES sa3 = { sizeof(sa3), nullptr, TRUE };
        if (CreatePipe(&hRead3, &hWrite3, &sa3, 0)) {
            STARTUPINFOW si3 = { sizeof(si3) };
            si3.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
            si3.hStdOutput = hWrite3;
            si3.hStdError = hWrite3;
            si3.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi3 = {0};
            wchar_t cmd3[] = L"vssadmin list shadows";
            if (CreateProcessW(nullptr, cmd3, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si3, &pi3)) {
                CloseHandle(hWrite3);
                std::string vssOutput;
                char buf[4096];
                DWORD bytesRead;
                while (ReadFile(hRead3, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    vssOutput += buf;
                }
                CloseHandle(hRead3);
                WaitForSingleObject(pi3.hProcess, 5000);
                CloseHandle(pi3.hProcess);
                CloseHandle(pi3.hThread);

                std::string vssLower = vssOutput;
                std::transform(vssLower.begin(), vssLower.end(), vssLower.begin(), ::tolower);
                // Count shadow copies
                size_t count = 0, pos = 0;
                while ((pos = vssLower.find("shadow copy id", pos)) != std::string::npos) {
                    count++;
                    pos++;
                }
                if (count > 0) {
                    r.findings.push_back({
                        "VOLUME_SHADOW",
                        std::to_string(count) + " shadow copies found",
                        50,
                        "Volume Shadow Copies exist ??? may contain hidden cheat artifacts"
                    });
                    r.score += 10;
                }
            } else {
                CloseHandle(hWrite3);
                CloseHandle(hRead3);
            }
        }
    }

    UpdateProgress(30, 31);

    // ========================================================================
    // PHASE 30: NTFS Alternate Data Streams ??? hidden data in files
    // ========================================================================
    {
        wchar_t localAppData2[MAX_PATH], tempDir2[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData2);
        GetTempPathW(MAX_PATH, tempDir2);

        std::vector<std::wstring> adsDirs = { localAppData2, tempDir2 };
        for (const auto& dir : adsDirs) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(dir)) {
                    if (!entry.is_regular_file()) continue;
                    std::wstring fn = entry.path().filename().wstring();
                    std::wstring ext = entry.path().extension().wstring();
                    std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);
                    if (ext != L".exe" && ext != L".dll") continue;

                    WIN32_FIND_STREAM_DATA fsd;
                    HANDLE hFind = FindFirstStreamW(entry.path().c_str(), FindStreamInfoStandard, &fsd, 0);
                    if (hFind == INVALID_HANDLE_VALUE) continue;

                    int streamCount = 0;
                    do {
                        std::wstring streamName(fsd.cStreamName);
                        if (streamName != L"::$DATA") {
                            streamCount++;
                        }
                    } while (FindNextStreamW(hFind, &fsd));
                    FindClose(hFind);

                    if (streamCount > 0) {
                        r.findings.push_back({
                            "NTFS_ADS",
                            WideToAnsi(fn),
                            85,
                            "Alternate Data Streams found on executable ??? " + std::to_string(streamCount) + " hidden stream(s)"
                        });
                        r.score += 30;
                    }
                }
            } catch (...) {}
        }
    }

    // ========================================================================
    // PHASE 31: Bootstrapper Detection
    // Safely detects alternative Roblox bootstrappers without flagging them as cheats
    // ========================================================================
    {
        wchar_t localAppData[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
        std::vector<std::wstring> bootstrappers = {L"Bloxstrap", L"Fishstrap", L"Voidstrap", L"Frostrap", L"FrostStrap", L"Macaw"};
        for (const auto& strap : bootstrappers) {
            std::wstring path = std::wstring(localAppData) + L"\\" + strap;
            if (std::filesystem::exists(path)) {
                // To avoid false positives on uninstalled leftovers, confirm there's an actual exe inside
                bool hasExecutable = false;
                try {
                    for (const auto& entry : std::filesystem::directory_iterator(path)) {
                        if (entry.is_regular_file() && Lower(entry.path().extension().wstring()) == L".exe") {
                            hasExecutable = true;
                            break;
                        }
                    }
                } catch (...) {}

                if (hasExecutable) {
                    r.findings.push_back({
                        "BOOTSTRAPPER",
                        WideToAnsi(strap),
                        0,
                        "Alternative Roblox Bootstrapper installed at: " + WideToAnsi(path)
                    });
                }
            }
        }
    }

    // ========================================================================
    // PHASE 32: Hypervisor Detection (RDTSC Timing Attack)
    // Detects Ring -1 stealth hypervisors used to intercept execution environments
    // ========================================================================
    {
        unsigned long long tsc_pre = __rdtsc();
        int cpuInfo[4];
        __cpuid(cpuInfo, 1);
        unsigned long long tsc_post = __rdtsc();
        unsigned long long delta = tsc_post - tsc_pre;
        
        // Typical bare-metal CPUID takes ~50-200 cycles. A VM-Exit context switch takes >750.
        // NOTE: Windows 11 VBS / Core Isolation heavily uses Hyper-V which causes this to spike to ~1000-5000 cycles.
        if (delta > 750) {
            r.findings.push_back({
                "HYPERVISOR_DETECTED",
                "RDTSC Timing Anomaly",
                30,
                "CPUID instruction took " + std::to_string(delta) + " cycles. VM-Exit intercept likely (Common with Windows 11 VBS / Hyper-V)."
            });
            r.score += 0;
        }
    }

    // ========================================================================
    // PHASE 33: BYOVD (Bring Your Own Vulnerable Driver) Detection
    // Queries Event Log ID 7045 (Service Installed) for anomalous kernel drivers
    // ========================================================================
    {
        EVT_HANDLE hResults = EvtQuery(NULL, L"System", L"*[System[(EventID=7045)]]", EvtQueryChannelPath | EvtQueryReverseDirection);
        if (hResults) {
            EVT_HANDLE hEvents[10];
            DWORD returned = 0;
            // Only check the 10 most recent service installs
            if (EvtNext(hResults, 10, hEvents, INFINITE, 0, &returned)) {
                for (DWORD i = 0; i < returned; i++) {
                    DWORD bufSize = 0;
                    DWORD propCount = 0;
                    EvtRender(NULL, hEvents[i], EvtRenderEventXml, bufSize, NULL, &bufSize, &propCount);
                    if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
                        std::vector<wchar_t> buffer(bufSize);
                        if (EvtRender(NULL, hEvents[i], EvtRenderEventXml, bufSize, buffer.data(), &bufSize, &propCount)) {
                            std::wstring xml(buffer.data());
                            // If it's a kernel driver and not in System32 (e.g. loaded from Temp/Downloads)
                            if (xml.find(L"Kernel Mode Driver") != std::wstring::npos && 
                                (xml.find(L"\\AppData\\") != std::wstring::npos || xml.find(L"\\Temp\\") != std::wstring::npos)) {
                                r.findings.push_back({
                                    "BYOVD_EXPLOIT",
                                    "Vulnerable Driver Load Detected",
                                    95,
                                    "Suspicious kernel driver installed from AppData/Temp."
                                });
                                r.score += 50;
                                break; // Only flag once
                            }
                        }
                    }
                    EvtClose(hEvents[i]);
                }
            }
            EvtClose(hResults);
        }
    }
    // ========================================================================
    // PHASE 34: Hosts File Telemetry Scan
    // Detects Roblox crash/analytics servers being routed to localhost
    // ========================================================================
    {
        wchar_t sysDir[MAX_PATH];
        if (GetSystemDirectoryW(sysDir, MAX_PATH)) {
            std::wstring hostsPath = std::wstring(sysDir) + L"\\drivers\\etc\\hosts";
            std::ifstream file(WideToAnsi(hostsPath));
            if (file.is_open()) {
                std::string line;
                while (std::getline(file, line)) {
                    std::string lowerLine = line;
                    std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
                    if (lowerLine.find("roblox.com") != std::string::npos || lowerLine.find("roblox.net") != std::string::npos) {
                        if (lowerLine.find("127.0.0.1") != std::string::npos || lowerLine.find("0.0.0.0") != std::string::npos) {
                            r.findings.push_back({
                                "TELEMETRY_BLOCK",
                                "Roblox Hosts File Tampering",
                                85,
                                "Roblox telemetry server blocked: " + line
                            });
                            r.score += 50;
                            break;
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // PHASE 35: Discord RPC / LevelDB Cache Scan
    // Detects cheat rich presence logged by Discord
    // ========================================================================
    {
        wchar_t appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
            std::vector<std::wstring> discordDirs = { L"\\discord", L"\\discordcanary", L"\\discordptb" };
            for (const auto& dir : discordDirs) {
                std::wstring ldbPath = std::wstring(appData) + dir + L"\\Local Storage\\leveldb";
                if (std::filesystem::exists(ldbPath)) {
                    for (const auto& entry : std::filesystem::directory_iterator(ldbPath)) {
                        if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                            std::ifstream file(entry.path().string(), std::ios::binary);
                            if (file.is_open()) {
                                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                std::string lowerContent = content;
                                std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
                                for (const auto& keyword : BROWSER_CHEAT_URLS) {
                                    if (lowerContent.find(keyword) != std::string::npos) {
                                        r.findings.push_back({
                                            "DISCORD_RPC_CACHE",
                                            "Discord RPC Cheat Log",
                                            80,
                                            "Discord logged execution of: " + keyword
                                        });
                                        r.score += 30;
                                        break; // Only flag once per file
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // ========================================================================
    // PHASE 36: USB Plug-and-Pull Forensics
    // Detects if a USB drive was recently removed (common for portable cheats)
    // ========================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD subKeys = 0;
            DWORD maxSubKeyLen = 0;
            if (RegQueryInfoKeyW(hKey, NULL, NULL, NULL, &subKeys, &maxSubKeyLen, NULL, NULL, NULL, NULL, NULL, NULL) == ERROR_SUCCESS) {
                for (DWORD i = 0; i < subKeys; i++) {
                    std::vector<wchar_t> keyName(maxSubKeyLen + 1);
                    DWORD keyNameLen = maxSubKeyLen + 1;
                    FILETIME lastWriteTime;
                    if (RegEnumKeyExW(hKey, i, keyName.data(), &keyNameLen, NULL, NULL, NULL, &lastWriteTime) == ERROR_SUCCESS) {
                        FILETIME ftNow;
                        GetSystemTimeAsFileTime(&ftNow);
                        
                        ULARGE_INTEGER ulNow, ulLastWrite;
                        ulNow.LowPart = ftNow.dwLowDateTime;
                        ulNow.HighPart = ftNow.dwHighDateTime;
                        ulLastWrite.LowPart = lastWriteTime.dwLowDateTime;
                        ulLastWrite.HighPart = lastWriteTime.dwHighDateTime;
                        
                        unsigned long long diff = ulNow.QuadPart - ulLastWrite.QuadPart;
                        unsigned long long diffHours = diff / 10000000ULL / 3600ULL;
                        
                        if (diffHours < 24) {
                            std::wstring wideKeyName = keyName.data();
                            r.findings.push_back({
                                "USB_PLUG_PULL",
                                "Recent USB Device Activity",
                                40,
                                "A USB device was plugged/unplugged within 24h: " + WideToAnsi(wideKeyName)
                            });
                        }
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }

    // ========================================================================
    // PHASE 37: Roblox Crash Log Forensics
    // Detects injected DLL traces in Roblox crash telemetry
    // ========================================================================
    {
        wchar_t localAppData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, localAppData))) {
            std::wstring logPath = std::wstring(localAppData) + L"\\Roblox\\logs";
            if (std::filesystem::exists(logPath)) {
                for (const auto& entry : std::filesystem::directory_iterator(logPath)) {
                    if (entry.path().extension() == ".log") {
                        auto ftime = std::filesystem::last_write_time(entry);
                        auto sctp = std::chrono::time_point_cast<std::chrono::system_clock::duration>(ftime - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now());
                        std::time_t ctime = std::chrono::system_clock::to_time_t(sctp);
                        
                        // Only check logs modified in the last 48 hours
                        if (std::time(nullptr) - ctime < 48 * 3600) {
                            std::ifstream file(entry.path().string());
                            if (file.is_open()) {
                                std::string line;
                                while (std::getline(file, line)) {
                                    std::string lowerLine = line;
                                    std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
                                    for (const auto& sig : CHEAT_FILE_SIGNATURES) {
                                        if (lowerLine.find(WideToAnsi(sig)) != std::string::npos) {
                                            struct tm tm_info;
                                            localtime_s(&tm_info, &ctime);
                                            char timeBuf[64];
                                            std::strftime(timeBuf, sizeof(timeBuf), "%Y-%m-%d %H:%M:%S", &tm_info);

                                            r.findings.push_back({
                                                "ROBLOX_CRASH_LOG",
                                                "Cheat Exception in Crash Dump",
                                                80,
                                                "Roblox crashed while cheat was injected: " + WideToAnsi(sig) + " (Time: " + std::string(timeBuf) + ")"
                                            });
                                            r.score += 20;
                                            goto next_log;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    next_log:;
                }
            }
        }
    }
    // ========================================================================
    // PHASE 38: Secure Boot Validation
    // Detects if the system is vulnerable to UEFI bootkits (e.g., EfiGuard)
    // ========================================================================
    {
        // 8BE4DF61-93CA-11D2-AA0D-00E098032B8C is the standard EFI global variable GUID
        DWORD secureBootStatus = 0;
        if (GetFirmwareEnvironmentVariableW(L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}", &secureBootStatus, sizeof(secureBootStatus)) != 0) {
            if (secureBootStatus == 0) {
                r.findings.push_back({
                    "VULNERABLE_BOOT_STATE",
                    "Secure Boot Disabled",
                    90,
                    "System is vulnerable to UEFI bootkits (Ring-0 DMA exploits)."
                });
                r.score += 40;
            }
        }
    }

    // ========================================================================
    // PHASE 39: ETW (Event Tracing) Blindness Detection
    // Detects if a cheat patched EtwEventWrite to stop Windows telemetry
    // ========================================================================
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            FARPROC pEtwEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
            if (pEtwEventWrite) {
                // Read the first byte of the function in memory
                BYTE firstByte = *(BYTE*)pEtwEventWrite;
                
                // 0xC3 is the assembly instruction for 'ret' (Return)
                // If the first byte is a return, the function has been neutered.
                if (firstByte == 0xC3) {
                    r.findings.push_back({
                        "ETW_BLINDING",
                        "Telemetry Subsystem Patched",
                        100,
                        "EtwEventWrite in ntdll.dll has been overwritten with a RET instruction."
                    });
                    r.score += 60;
                }
            }
        }
    }

    UpdateProgress(39, 39);    // ========================================================================
    // SCORING + VERDICT
    // ========================================================================
    r.score = (std::min)(r.score, 100);
    if (r.score >= 80) r.verdict = "CONFIRMED CHEATER";
    else if (r.score >= 50) r.verdict = "LIKELY CHEATER";
    else if (r.score >= 25) r.verdict = "SUSPICIOUS";
    else r.verdict = "CLEAN";

    return r;
}

// ============================================================================
// 6. DISPLAY & FORMATTING
// ============================================================================

std::string GetFriendlyCategory(const std::string& cat) {
    if (cat == "ROBLOX_MODULE" || cat == "ROBLOX_MEMORY") return "ROBLOX";
    if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY") return "HISTORY";
    if (cat == "BAM_REGISTRY" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "UNINSTALL_KEY" || cat == "USERASSIST" || cat == "AMCACHE") return "REGISTRY";
    if (cat == "DNS_CACHE" || cat == "FIREWALL_RULE" || cat == "VIRTUAL_MACHINE_MAC" || cat == "REMOTE_DESKTOP_TOOL" || cat == "DUAL_PC_STREAMING" || cat == "STREAMING_PORT") return "NETWORK";
    if (cat == "DELETED_CHEAT" || cat == "SUSPICIOUS_TEMP_PE" || cat == "RECENT_FILE" || cat == "CHEAT_FOLDER" || cat == "RECYCLE_BIN" || cat == "NTFS_ADS" || cat == "TIMESTOMPING" || cat == "HIGH_ENTROPY_PE") return "FILES";
    if (cat == "DMA_CARD") return "HARDWARE";
    if (cat == "SRUM_DATABASE" || cat == "VOLUME_SHADOW") return "FORENSICS";
    return "SYSTEM";
}

std::string PadRight(std::string str, size_t len) {
    if (str.length() >= len) return str;
    return str + std::string(len - str.length(), ' ');
}

std::string GetBroadCategory(const Finding& f) {
    std::wstring lowerDesc = Lower(AnsiToWide(f.description));
    std::wstring lowerEvid = Lower(AnsiToWide(f.evidence));
    std::string cat = f.category;

    if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY") return "Search History";

    if (cat == "BOOTSTRAPPER" || 
        lowerDesc.find(L"bloxstrap") != std::wstring::npos || lowerEvid.find(L"bloxstrap") != std::wstring::npos ||
        lowerDesc.find(L"voidstrap") != std::wstring::npos || lowerEvid.find(L"voidstrap") != std::wstring::npos ||
        lowerDesc.find(L"frostrap") != std::wstring::npos || lowerEvid.find(L"frostrap") != std::wstring::npos ||
        lowerDesc.find(L"fishstrap") != std::wstring::npos || lowerEvid.find(L"fishstrap") != std::wstring::npos) {
        return "Bootstrappers";
    }

    if (cat == "VIRTUAL_MACHINE_MAC" || cat == "DMA_CARD" || cat == "STREAMING_PORT" || cat == "DUAL_PC_STREAMING" ||
        lowerDesc.find(L"bypass") != std::wstring::npos || lowerEvid.find(L"bypass") != std::wstring::npos ||
        lowerDesc.find(L"spoofer") != std::wstring::npos || lowerEvid.find(L"spoofer") != std::wstring::npos ||
        lowerDesc.find(L"dma") != std::wstring::npos || lowerEvid.find(L"dma") != std::wstring::npos) {
        return "Bypassers";
    }

    if (cat != "SYSTEM" && cat != "NETWORK") {
        return "Injectors / Executors";
    }

    return "Other Findings";
}

void ShowResult(const CheatResult& r, const std::string& name, const std::string& hwid) {
    system("cls");
    std::cout << "\n";

    if (r.score >= 80) {
        system("color 0C");
        std::cout << "    ========================================================\n";
        std::cout << "              ** CONFIRMED CHEATER - " << r.score << "/100 **\n";
        std::cout << "    ========================================================\n\n";
    } else if (r.score >= 50) {
        system("color 0C");
        std::cout << "    ========================================================\n";
        std::cout << "              ** LIKELY CHEATING - " << r.score << "/100 **\n";
        std::cout << "    ========================================================\n\n";
    } else if (r.score >= 25) {
        system("color 0E");
        std::cout << "    ========================================================\n";
        std::cout << "              ** SUSPICIOUS - " << r.score << "/100 **\n";
        std::cout << "    ========================================================\n\n";
    } else {
        system("color 0A");
        std::cout << "    ========================================================\n";
        std::cout << "              ** CLEAN - NO CHEATING DETECTED **\n";
        std::cout << "    ========================================================\n\n";
    }

    std::cout << "    Player: " << ui::GOLD << name << ui::RESET << "\n";
    std::cout << "    HWID:   " << ui::GRAY << hwid << ui::RESET << "\n\n";

    if (r.findings.empty()) {
        ui::PrintSuccess("No cheating indicators found.");
        std::cout << "\n";
    } else {
        std::cout << "    FINDINGS (" << r.findings.size() << "):\n";
        std::cout << "    " << ui::DARK_GOLD << std::string(56, '-') << ui::RESET << "\n\n";

        std::map<std::string, std::vector<Finding>> grouped;
        for (const auto& f : r.findings) grouped[GetBroadCategory(f)].push_back(f);
        
        std::vector<std::string> order = {"Bootstrappers", "Injectors / Executors", "Bypassers", "Search History", "Other Findings"};

        for (const auto& grpName : order) {
            if (grouped.find(grpName) != grouped.end() && !grouped[grpName].empty()) {
                std::string upperName = grpName;
                for (auto & c: upperName) c = tolower(c);
                std::cout << "    [" << upperName << "]\n";
                for (const auto& f : grouped[grpName]) {
                    std::string conf;
                    if (f.confidence >= 90) conf = ui::RED + "[CONFIRMED]";
                    else if (f.confidence >= 70) conf = ui::DARK_GOLD + "[HIGH]";
                    else if (f.confidence >= 50) conf = ui::GOLD + "[MEDIUM]";
                    else if (f.confidence > 0) conf = ui::GRAY + "[LOW]";
                    else conf = ui::GRAY + "[INFO]";
                    
                    std::cout << "      " << conf << ui::RESET << " " << f.description << "\n";
                    if (!f.evidence.empty()) std::cout << "          " << ui::DARK_GOLD << f.evidence << ui::RESET << "\n";
                    std::cout << "\n";
                }
                std::cout << "\n";
            }
        }
        std::cout << "    " << ui::DARK_GOLD << std::string(56, '-') << ui::RESET << "\n\n";
    }

    std::cout << "    " << ui::GOLD << std::string(56, '=') << ui::RESET << "\n";
    std::cout << "    VERDICT: " << ui::RED << r.verdict << ui::RESET << "\n";
    if (r.score >= 80) std::cout << "    ACTION:  " << ui::RED << "BAN IMMEDIATELY" << ui::RESET << "\n";
    else if (r.score >= 50) std::cout << "    ACTION:  " << ui::DARK_GOLD << "INVESTIGATE FURTHER" << ui::RESET << "\n";
    else if (r.score >= 25) std::cout << "    ACTION:  " << ui::GOLD << "MONITOR CLOSELY" << ui::RESET << "\n";
    else std::cout << "    ACTION:  " << ui::GREEN << "NONE - PLAYER IS CLEAN" << ui::RESET << "\n";
    std::cout << "    " << ui::GOLD << std::string(56, '=') << ui::RESET << "\n\n";
}

// ============================================================================
// 7. BUILD REPORT STRING ??? used for local save and server POST
// ============================================================================

std::string BuildReportText(const CheatResult& r, const std::string& name, const std::string& hwid) {
    std::ostringstream rpt;
    rpt << "ROBLOX SCAN REPORT\n";
    rpt << "========================\n";
    rpt << "Player: " << name << "\n";
    rpt << "HWID: " << hwid << "\n";
    rpt << "Score: " << r.score << "/100\n";
    rpt << "Verdict: " << r.verdict << "\n";
    rpt << "Time: " << GetTimestamp() << "\n\n";

    rpt << "FINDINGS (" << r.findings.size() << "):\n\n";
    
    std::map<std::string, std::vector<Finding>> grouped;
    for (const auto& f : r.findings) grouped[GetBroadCategory(f)].push_back(f);
    std::vector<std::string> order = {"Bootstrappers", "Injectors / Executors", "Bypassers", "Search History", "Other Findings"};

    for (const auto& grpName : order) {
        if (grouped.find(grpName) != grouped.end() && !grouped[grpName].empty()) {
            std::string upperName = grpName;
            for (auto & c: upperName) c = tolower(c);
            rpt << "[" << upperName << "]\n";
            for (const auto& f : grouped[grpName]) {
                std::string conf;
                if (f.confidence >= 90) conf = "CONFIRMED";
                else if (f.confidence >= 70) conf = "HIGH";
                else if (f.confidence >= 50) conf = "MEDIUM";
                else if (f.confidence > 0) conf = "LOW";
                else conf = "INFO";
                
                rpt << "  [" << conf << "] " << f.description << "\n";
                if (!f.evidence.empty()) rpt << "              " << f.evidence << "\n";
                rpt << "\n";
            }
            rpt << "\n";
        }
    }

    if (r.findings.empty()) {
        rpt << "  No cheating indicators found.\n";
    }

    rpt << "\n========================\n";
    rpt << "VERDICT: " << r.verdict << "\n";
    if (r.score >= 80) rpt << "ACTION:  BAN IMMEDIATELY\n";
    else if (r.score >= 50) rpt << "ACTION:  INVESTIGATE FURTHER\n";
    else if (r.score >= 25) rpt << "ACTION:  MONITOR CLOSELY\n";
    else rpt << "ACTION:  NONE - PLAYER IS CLEAN\n";

    return rpt.str();
}

// ============================================================================
// 8. SAVE REPORT ??? Saves to reports/ directory next to the exe
// ============================================================================

void SaveReport(const CheatResult& r, const std::string& name, const std::string& hwid) {
    std::wstring exeDir = GetExeDirectory();
    std::wstring reportDir = exeDir + L"\\reports";
    CreateDirectoryW(reportDir.c_str(), NULL);

    std::wstring reportPath = reportDir + L"\\" + AnsiToWide(name) + L".txt";
    std::ofstream f(reportPath.c_str());
    if (f.is_open()) {
        f << BuildReportText(r, name, hwid);
        f.close();
    }
}

// ============================================================================
// 9. POST REPORT TO ADMIN SERVER ??? sends report back to your PC
// ============================================================================

bool PostReportToServer(const CheatResult& r, const std::string& name, const std::string& hwid,
                        const std::wstring& serverHost, INTERNET_PORT serverPort, DWORD flagSecure)
{
    std::string reportText = BuildReportText(r, name, hwid);

    // Build JSON payload
    std::ostringstream j;
    j << "{\"name\":\"" << JsonEscape(name) << "\",";
    j << "\"hwid\":\"" << JsonEscape(hwid) << "\",";
    j << "\"score\":" << r.score << ",";
    j << "\"verdict\":\"" << JsonEscape(r.verdict) << "\",";
    j << "\"findings_count\":" << r.findings.size() << ",";
    j << "\"report\":\"" << JsonEscape(reportText) << "\"}";

    std::string jsonStr = j.str();

    HINTERNET hSession = WinHttpOpen(L"RobloxScanner/4.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return false;

    HINTERNET hConnect = WinHttpConnect(hSession, serverHost.c_str(), serverPort, 0);
    if (!hConnect) { WinHttpCloseHandle(hSession); return false; }

    HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"POST", L"/report",
        nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flagSecure);
    if (!hRequest) { WinHttpCloseHandle(hConnect); WinHttpCloseHandle(hSession); return false; }

    const wchar_t* headers = L"Content-Type: application/json";
    BOOL sent = WinHttpSendRequest(hRequest, headers, -1L,
        (LPVOID)jsonStr.c_str(), (DWORD)jsonStr.size(), (DWORD)jsonStr.size(), 0);

    bool success = false;
    if (sent) {
        success = WinHttpReceiveResponse(hRequest, nullptr) != 0;
        if (success) {
            DWORD statusCode = 0;
            DWORD statusCodeSize = sizeof(statusCode);
            WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                WINHTTP_HEADER_NAME_BY_INDEX, &statusCode, &statusCodeSize, WINHTTP_NO_HEADER_INDEX);
            success = (statusCode >= 200 && statusCode < 300);
        }
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return success;
}

// ============================================================================
// AUTO-UPDATER
// ============================================================================
void CheckForUpdates(const std::string& currentVersion, const std::wstring& targetExeUrl) {
    std::cout << "    [*] Checking for updates...\n";
    HINTERNET hSession = WinHttpOpen(L"NatsuXAK/6.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) return;

    HINTERNET hConnect = WinHttpConnect(hSession, L"raw.githubusercontent.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
    if (hConnect) {
        HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/rahre/Roblox-Scanner/main/version.txt", nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
        if (hRequest) {
            if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hRequest, nullptr)) {
                DWORD size = 0;
                std::string fetchedVersion = "";
                do {
                    WinHttpQueryDataAvailable(hRequest, &size);
                    if (size > 0) {
                        char* buf = new char[size + 1];
                        ZeroMemory(buf, size + 1);
                        DWORD dl = 0;
                        WinHttpReadData(hRequest, buf, size, &dl);
                        fetchedVersion += std::string(buf, dl);
                        delete[] buf;
                    }
                } while (size > 0);
                
                // Trim fetchedVersion (spaces, newlines, null terminators)
                while (!fetchedVersion.empty() && (fetchedVersion.back() == '\r' || fetchedVersion.back() == '\n' || fetchedVersion.back() == ' ' || fetchedVersion.back() == '\0')) fetchedVersion.pop_back();

                if (!fetchedVersion.empty() && fetchedVersion != currentVersion) {
                    std::cout << "    [!] Update found! Version " << fetchedVersion << " is available.\n";
                    std::cout << "    [*] Downloading update...\n";
                    
                    HINTERNET hReqFile = WinHttpOpenRequest(hConnect, L"GET", targetExeUrl.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                    if (hReqFile && WinHttpSendRequest(hReqFile, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) && WinHttpReceiveResponse(hReqFile, nullptr)) {
                        wchar_t tempPath[MAX_PATH];
                        GetTempPathW(MAX_PATH, tempPath);
                        std::wstring updatePath = std::wstring(tempPath) + L"NatsuXAK_update.exe";
                        
                        HANDLE hFile = CreateFileW(updatePath.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
                        if (hFile != INVALID_HANDLE_VALUE) {
                            DWORD bytesRead = 0;
                            do {
                                WinHttpQueryDataAvailable(hReqFile, &size);
                                if (size > 0) {
                                    char* buf = new char[size];
                                    if (WinHttpReadData(hReqFile, buf, size, &bytesRead)) {
                                        DWORD bytesWritten = 0;
                                        WriteFile(hFile, buf, bytesRead, &bytesWritten, nullptr);
                                    }
                                    delete[] buf;
                                }
                            } while (size > 0);
                            CloseHandle(hFile);

                            std::cout << "    [+] Update downloaded! Restarting...\n";

                            wchar_t selfPath[MAX_PATH];
                            GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

                            // Spawn a batch script to replace the old executable
                            std::wstring batPath = std::wstring(tempPath) + L"updater.bat";
                            std::wofstream bat(batPath.c_str());
                            bat << L"@echo off\n"
                                << L"timeout /t 2 /nobreak >nul\n"
                                << L"del /f /q \"" << selfPath << L"\"\n"
                                << L"move /y \"" << updatePath << L"\" \"" << selfPath << L"\"\n"
                                << L"start \"\" \"" << selfPath << L"\"\n"
                                << L"del \"%~f0\"\n";
                            bat.close();

                            STARTUPINFOW si;
                            ZeroMemory(&si, sizeof(si));
                            si.cb = sizeof(si);
                            si.dwFlags = STARTF_USESHOWWINDOW;
                            si.wShowWindow = SW_HIDE;
                            PROCESS_INFORMATION pi;
                            ZeroMemory(&pi, sizeof(pi));

                            std::wstring cmd = L"cmd.exe /c \"" + batPath + L"\"";
                            std::vector<wchar_t> cmdBuf(cmd.begin(), cmd.end());
                            cmdBuf.push_back(L'\0');

                            if (CreateProcessW(nullptr, cmdBuf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                                CloseHandle(pi.hProcess);
                                CloseHandle(pi.hThread);
                            }
                            
                            exit(0);
                        }
                    }
                    if (hReqFile) WinHttpCloseHandle(hReqFile);
                }
            }
            WinHttpCloseHandle(hRequest);
        }
        WinHttpCloseHandle(hConnect);
    }
    WinHttpCloseHandle(hSession);
}

// ============================================================================
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    // Set console dimensions but increase buffer height significantly so users can scroll up
    system("mode con cols=140 lines=50");
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut != INVALID_HANDLE_VALUE) {
        CONSOLE_SCREEN_BUFFER_INFO csbi;
        if (GetConsoleScreenBufferInfo(hOut, &csbi)) {
            csbi.dwSize.Y = 9999;
            SetConsoleScreenBufferSize(hOut, csbi.dwSize);
        }
    }
    // Anti-RE: detect debuggers, disassemblers, process monitors
    // if (AntiDebugCheck()) {
    //     MessageBoxW(nullptr, L"The application encountered a critical fatal exception (0xC0000005) and must close.", L"Fatal Error", MB_ICONERROR);
    //     return 1;
    // }
    
    // WipePEHeader();
    
    // if (!ValidateParentProcess()) {
    //     MessageBoxW(nullptr, L"The application encountered a critical fatal exception (0xC0000005) and must close.", L"Fatal Error", MB_ICONERROR);
    //     return 1;
    // }
    DWORD crc = ComputeTextCRC32();

    SetConsoleTitleW(L"NatsuXAK Scanner");
    ui::EnableANSI();
    ui::BootAnimation();
    ui::PrintHeader("NatsuXAK Scanner");
    
    // Auto Update check (Version 6.0)
    CheckForUpdates("6.1", L"/rahre/Roblox-Scanner/main/Owner/scanner.exe");

    std::string name;
    if (argc > 1) {
        name = argv[1];
    } else {
        name = ui::GetInput("Enter your name: ");
    }

    if (name.empty()) {
        std::cout << "    [-] Name required.\n";
        std::cin.get();
        return 1;
    }

    // Server authorization & local fallback
    std::cout << "    Checking authorization...\n";
    std::string playerType = "";

    
    std::wstring serverHost = L"roblox-scanner-hioo.onrender.com";
    INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTPS_PORT;
    DWORD flagSecure = WINHTTP_FLAG_SECURE;
    
    HINTERNET hSession = WinHttpOpen(L"RobloxScanner/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (hSession) {
        WinHttpSetTimeouts(hSession, 60000, 60000, 60000, 60000);
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
                    } else { std::cout << "    [-] WinHttpReceiveResponse failed: " << GetLastError() << "\n"; }
                } else { std::cout << "    [-] WinHttpSendRequest failed: " << GetLastError() << "\n"; }
                WinHttpCloseHandle(hSrvReq);
            } else { std::cout << "    [-] WinHttpOpenRequest failed: " << GetLastError() << "\n"; }
            WinHttpCloseHandle(hSrvConnect);
        } else { std::cout << "    [-] WinHttpConnect failed: " << GetLastError() << "\n"; }
        WinHttpCloseHandle(hSession);
    } else { std::cout << "    [-] WinHttpOpen failed: " << GetLastError() << "\n"; }

    // Trim playerType from any source (local file, HTTP response)
    while (!playerType.empty() && (playerType.back() == ' ' || playerType.back() == '\r' || playerType.back() == '\n' || playerType.back() == '\t'))
        playerType.pop_back();
    while (!playerType.empty() && (playerType.front() == ' ' || playerType.front() == '\r' || playerType.front() == '\n' || playerType.front() == '\t'))
        playerType.erase(playerType.begin());
    // Uppercase for consistent comparison
    std::transform(playerType.begin(), playerType.end(), playerType.begin(), ::toupper);
    
    // Server now returns 'PC:checker_name' or 'TEST:checker_name'
    std::string playerTypeOnly = playerType;
    size_t colonPos = playerType.find(':');
    if (colonPos != std::string::npos) {
        playerTypeOnly = playerType.substr(0, colonPos);
    }

    if (playerTypeOnly == "INVALID") {
        std::cout << "    [-] Player not authorized. Scan aborted.\n";
        std::cout << "    Press any key to exit...\n";
        system("pause >nul");
        return 1;
    }
    if (playerTypeOnly.empty()) {
        std::cout << "    [-] Could not reach admin server. Scan aborted.\n";
        std::cout << "    Press any key to exit...\n";
        system("pause >nul");
        return 1;
    }

    std::cout << "    [+] Welcome, " << name << "\n\n";

    std::string hwid = GetHardwareID();
    std::cout << "    Scanning system integrity...\n\n";
    Sleep(300);

    CheatResult result = FullScan();

    std::cout << "\n\n    [*] Done.\n";
    Sleep(200);


    // POST report to admin server if tunnel or local server is available
    std::cout << "    Sending report to admin server...\n";
    bool reportSent = PostReportToServer(result, name, hwid, serverHost, serverPort, flagSecure);
    if (reportSent) {
        std::cout << "    [+] Report delivered to admin server.\n\n";
    } else {
        std::cout << "    [!] Could not reach admin server.\n\n";
    }

    if (playerTypeOnly != "TEST") {
        // ALWAYS self-delete ??? one-time use
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

        // Spawn a background CMD that loops every 2 seconds trying to delete the file
        // This ensures that even if they click the 'X' on the window to force close it,
        // the background process will delete the file the moment the lock is released.
        wchar_t cmdLine[2048];
        swprintf_s(cmdLine, 2048,
            L"cmd.exe /c (for /l %%i in (1,1,100) do (ping 127.0.0.1 -n 2 > nul & del /f /q \"%s\" & if not exist \"%s\" exit))",
            selfPath, selfPath);

        STARTUPINFOW si;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi;
        ZeroMemory(&pi, sizeof(pi));

        BOOL created = CreateProcessW(
            nullptr, cmdLine, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);

        if (created) {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
        } else {
            MoveFileExW(selfPath, nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
        }
    } else {
        std::cout << "    [TEST MODE] Auto-delete disabled.\n\n";
    }

    std::cout << "    Press any key to exit...\n";
    system("pause >nul");

    return 0;
}
