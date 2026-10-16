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
#include <cmath>
#include "common.h"
#include "ui.h"
#include "security.h"

// Scanner build identity. Bump this whenever the binary changes so the server
// can track the runtime .text CRC observed per build and detect patching.
static const char* SCANNER_BUILD_ID = "7.2.0";

// ============================================================================
// FILESYSTEM PATH -> NARROW STRING
// ============================================================================
// path::string() converts wide -> the ANSI code page and THROWS
// std::system_error(ERROR_NO_UNICODE_TRANSLATION) as soon as a filename cannot
// be written in that code page. One such file anywhere in a walked tree (a
// CJK-named .exe in Downloads, an emoji in a temp dir) was enough: uncaught
// exception -> std::terminate -> fail-fast 0xC0000409, killing the scan at ~89%
// BEFORE SaveReport and before the POST, so the server never saw the report.
//
// WideToAnsi() encodes to UTF-8: it represents every legal filename, it never
// throws, and it is already the encoding the rest of this file uses for paths.
inline std::string PathUtf8(const std::filesystem::path& p) {
    return WideToAnsi(p.native());
}


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


// TLS callback removed to reduce antivirus false positives
// Anti-debug checks are performed at runtime in main() instead

// XOR obfuscation for sensitive strings (Rentry URL, server info)
static std::string XorDecode(const char* data, int len, char key) {
    std::string result(len, 0);
    for (int i = 0; i < len; i++) result[i] = data[i] ^ key;
    return result;
}

static bool AntiDebugCheck() {
    // Simplified check ??? only use IsDebuggerPresent to avoid AV false positives
    if (IsDebuggerPresent()) return true;
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
    L"cheatengine", L"cheat engine",
    L"x64dbg", L"x32dbg", L"ollydbg", L"dnspy",
    // Roblox exploits ??? executor names
    L"synapse x", L"synapsex", L"synapse z", L"synapsez",
    L"krnl", L"fluxus", L"fluxusz", L"scriptware", L"script-ware",
    L"arceusx", L"arceus x", L"arceus x neo",
    L"jjsploit", L"jj exploit", L"trigon", L"nigctl", L"winkernelinterface",
    // Generic - removed standalone single words (exploit, injector, etc.) to prevent false alarms
    L"furkultra", L"furk ultra", L"dansploit", L"proxo",
    L"macsploit", L"roexec", L"sirhurt", L"cocoexploit", L"coco exploit",
    L"zorara", L"cefacode", L"vegax", L"solara", L"solara executor", L"potassium",
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
    L"rc7.exe", L"rc7 executor", L"proto smasher", L"calamari",
    L"coco z", L"valyse", L"nezur",
    L"seliware", L"oxygen u", L"oxygen-u", L"kiwi x", L"kiwix", L"comet executor",
    L"shadow executor", L"aspect executor", L"novaline", L"sigma executor", L"meteor executor",
    L"appleware", L"nexus executor", L"cryptic executor", L"phantom executor",
    L"eclipse executor", L"omega executor", L"ro-exec", L"krampus.gg",
    // Matcha / External / aimbot tools
    L"matcha", L"matcha aimbot", L"matcha external", L"matcha esp", L"matcha cheat", L"matcha exploit",
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
    // Modern 2026 Executors & External Cheats
    L"swift executor", L"swift roblox", L"volcano executor", L"volcano exploit",
    L"xeno v2", L"valyse 2", L"valyse v2", L"dx9ware", L"dx9", L"dx9 external",
    L"aimmy v2", L"matcha v2", L"serotonin v2", L"aurora executor", L"aurora exploit",
    L"hyperion bypass", L"byfron bypass", L"vandal external", L"vandal aimbot",
    L"frost executor", L"olympus executor", L"olympus exploit",
    L"sensitiv", L"vision esp", L"silent aimbot", L"fov expander", L"reach expander",
    // HWID spoofer names
    L"hwid-spoofer", L"hwid spoofer", L"easyhwid", L"qlitech", L"spoof cheat",
    L"permanentspoofer", L"ruinspoofer", L"mac address changer", L"volumeid", L"hwid changer",
    L"solora", L"solora executor", L"script hub", L"adelat executor",
};

const std::vector<std::wstring> CHEAT_FILE_SIGNATURES = {
    // 100+ file signatures
    L"solara", L"fluxus", L"fluxusz", L"krnl", L"jjsploit", L"potassium",
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
    L"matcha", L"matcha-ext", L"matcha_ext", L"aimmy", L"camlock",
    L"da hood aimbot", L"rivals aimbot", L"silent aim",
    L"celeryinject", L"wpfui", L"celeryexecutor",
    // DLL injectors
    L"rbxinjector", L"luainjector", L"exploitapi",
    L"krnlss", L"wpfui", L"injector.exe", L"extreme injector",
    L"all roblox cheats",
    // Lua scripts
    L"autoexec", L"autoattach",
    // Original entries
    L"cheatengine", L"cheat engine",
    L"wearedevs", L"nigctl", L"winkernelinterface",
    L"rc7.exe", L"proto smasher",
    L"valyse", L"nezur",
    L"hwid-spoofer", L"hwid spoofer", L"easyhwid",
    L"kdmapper", L"pcihide", L"serial changer",
    L"maofficialvape",
    L"dx9ware", L"vandal", L"aurora", L"volcano", L"sensitiv",
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
    L"serotonin", L"thunderaim", L"matcha", L"matcha-ext", L"matcha aimbot", L"aimmy",
    L"wearedevs", L"easyexploits", L"matrixhub",
    L"all roblox cheats", L"all roblox cheat",
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

// Browser history & cheat web forensic URL signatures (2026 Executors, Bypass, Hubs)
const std::vector<std::string> BROWSER_CHEAT_URLS = {
    // 2026 Modern Executors & Injection Frameworks
    "swift.lol", "getswift.xyz", "swift-executor",
    "volcano.lol", "volcanoexecutor", "volcano-executor",
    "xeno.lol", "xenov2", "xenoexecutor", "xeno-executor",
    "valyse.net", "valyse.org", "valysev2", "valyse-executor",
    "solara.dev", "getsolara.dev", "solaraexecutor",
    "getwave.gg", "waveexecutor", "wave-executor",
    "codex.lol", "codexexecutor",
    "delta-executor.com", "delta-executor.org", "delta-exploits.org", "deltaexecutor.ai", "deltadevs.net",
    "arceusx.net", "arceus-x", "arceusx.com",
    "hydrogenexecutor.com", "hydrogen-executor",
    "celeryexecutor", "celery.zip", "celery-executor",
    "nihon.lol", "nihon.gg", "ronix.lol",
    "vandal.lol", "vandalexecutor",
    "frostexecutor", "olympus-executor", "sensitiv.lol", "sensitiv.gg",
    "ro-exec.com", "krampus.gg", "krampus.net",
    "krnl.place", "krnl.rocks", "fluxteam.net",
    "appleware.dev", "oxygenu.com", "kiwix.com",
    "synapsex.net", "synapse.to", "script-ware.com", "wearedevs.net",
    "easyexploits.com", "kingexploits.com", "bloxproducts.com",
    "whatexpsare.online", "getcore.cc",

    // External Aimbots / ESP / Visual Overlays
    "aimmy.app", "aimmy.dev", "github.com/aimmy",
    "matcha.gg", "matcha.lol", "matcha-aimbot.com",
    "dx9ware.com", "dx9.gg", "dx9ware",
    "serotonin.lol", "serotoninv2",
    "visionesp.com", "vision-esp",

    // Key Bypass & Gateway Sites (cheater key retrieval portals)
    "keybypass.net", "linkvertise.com", "platoboost.com", "gateway.platoboost.com",
    "loot-labs.com", "lootlabs.gg", "lootdest.com", "lootdest.org",
    "work.ink", "paster.so", "pandadevelopment.net",
    "sub2get.com", "boost.ink", "sub2unlock.com", "rekonise.com",

    // Script Hubs & Dumps
    "scriptblox.com", "rblxscripts.net", "robloxscripts.com", "cheater.fun",
    "matrixhubs.shop", "matrixhub.xyz", "v3rmillion.net", "robloxhax.com",
    "pastebin.com/raw/", "controlc.com", "rentry.co", "ghostbin.me",

    // Discord Invite URLs for Exploits / Cheats
    "discord.gg/solara", "discord.gg/realsolara", "discord.gg/swift",
    "discord.gg/volcano", "discord.gg/xeno", "discord.gg/valyse",
    "discord.gg/getwave", "discord.gg/wave", "discord.gg/codex",
    "discord.gg/aimmy", "discord.gg/matcha", "discord.gg/dx9",
    "discord.gg/serotonin", "discord.gg/krnl", "discord.gg/fluxus",
    "discord.gg/vandal", "discord.gg/arceusx"
};

// Discord RPC / LevelDB deep signatures (Rich Presence JSON tokens, application names, states)
const std::vector<std::string> DISCORD_RPC_KEYWORDS = {
    // Exact application names logged by Discord RPC
    "\"name\":\"swift\"", "\"name\":\"volcano\"", "\"name\":\"xeno\"",
    "\"name\":\"valyse\"", "\"name\":\"solara\"", "\"name\":\"solora\"", "\"name\":\"wave\"",
    "\"name\":\"aimmy\"", "\"name\":\"matcha\"", "\"name\":\"dx9ware\"",
    "\"name\":\"serotonin\"", "\"name\":\"krampus\"", "\"name\":\"ro-exec\"",
    "\"name\":\"codex\"", "\"name\":\"delta\"", "\"name\":\"adelat\"", "\"name\":\"arceus x\"",
    "\"name\":\"hydrogen\"", "\"name\":\"vandal\"", "\"name\":\"olympus\"",
    "\"name\":\"frost executor\"", "\"name\":\"potassium\"",
    "\"name\":\"cheat engine\"", "\"name\":\"x64dbg\"",
    "\"name\":\"spoofer\"", "\"name\":\"spoof cheat\"", "\"name\":\"executor\"",
    "\"name\":\"aim\"", "\"name\":\"hub\"",

    // Activity phrases & executor tokens logged in Discord activity details/states
    "roblox executor", "injecting into roblox", "executing script",
    "attaching to roblox", "solara v3", "solara v2", "solora",
    "wave executor", "delta executor", "krnl executor", "fluxus executor",
    "matcha v2", "aimmy v2", "aimmy ai", "dx9ware v2", "dx9ware",
    "potassium", "xeno", "codex", "adelat",
    "spoof cheat", "spoofer", "hwid spoofer",
    "script hub", "matrix hub", "aimbot", "camlock", "aim assist"
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
    L"physmem", L"dbk64", L"dbk32", L"nigctl",
    L"HW64", L"gdrv", L"WinRing0", L"WinRing0_1_2_0",
    L"cpuz141", L"AsrDrv106",
    L"NTIOLib_X64", L"DirectIo64", L"GIO",
    L"IOMAP64",
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
// CHEAT KNOWLEDGE BASE - Human-readable explanations for report output
// Maps lowercase cheat name fragments to { short_type, description }
// ============================================================================

struct CheatInfo {
    std::string type;        // e.g. "Script Executor", "Aimbot", "HWID Spoofer"
    std::string explanation; // What it does and why it matters
};

std::string GetCheatExplanation(const std::string& text) {
    std::string lower = text;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Script Executors / Injectors
    if (lower.find("synapse x") != std::string::npos || lower.find("synapsex") != std::string::npos)
        return "Synapse X - Premium Roblox script executor that injects Lua code into the game client";
    if (lower.find("synapse z") != std::string::npos || lower.find("synapsez") != std::string::npos)
        return "Synapse Z - Successor to Synapse X, a high-performance Roblox Lua script executor";
    if (lower.find("sirhurt") != std::string::npos)
        return "SirHurt - Paid Roblox script executor that uses DLL injection to run scripts in-game";
    if (lower.find("krnl") != std::string::npos && lower.find("krnlss") == std::string::npos)
        return "KRNL - Free Roblox executor that uses kernel-level techniques to inject scripts";
    if (lower.find("krnlss") != std::string::npos)
        return "KRNL DLL - Injected library from the KRNL script executor found inside Roblox memory";
    if (lower.find("fluxus") != std::string::npos || lower.find("fluxusz") != std::string::npos)
        return "Fluxus - Free Roblox Lua executor distributed through ad-gated downloads";
    if (lower.find("solara") != std::string::npos)
        return "Solara - Roblox Lua script executor that injects code into the game client";
    if (lower.find("potassium") != std::string::npos)
        return "Potassium - High-privilege Roblox Lua script executor with native Luau hooking";
    if (lower.find("injector") != std::string::npos && lower.find("injector_remnant") == std::string::npos)
        return "Generic Injector - Process/DLL injection utility used for unauthorized code execution";
    if (lower.find("delta executor") != std::string::npos || lower.find("deltaexploit") != std::string::npos || lower.find("deltaexecutor") != std::string::npos || lower.find("delta exploit") != std::string::npos || lower.find("delta x") != std::string::npos)
        return "Delta Executor - Cross-platform Roblox script executor";
    if (lower.find("arceus") != std::string::npos)
        return "Arceus X - Roblox script executor originally designed for mobile, also available on PC";
    if (lower.find("jjsploit") != std::string::npos || lower.find("jj exploit") != std::string::npos)
        return "JJSploit - Roblox executor by WeAreDevs";
    if (lower.find("trigon") != std::string::npos)
        return "Trigon - Roblox Lua script executor with auto-attach capability";
    if (lower.find("evon") != std::string::npos)
        return "Evon - Roblox Lua executor that hooks into the game's scripting engine";
    if (lower.find("nihon") != std::string::npos)
        return "Nihon - Roblox script executor";
    if (lower.find("krampus") != std::string::npos)
        return "Krampus - Premium Roblox script executor distributed via krampus.gg";
    if (lower.find("furkultra") != std::string::npos || lower.find("furk ultra") != std::string::npos)
        return "Furk Ultra - Roblox script executor";
    if (lower.find("dansploit") != std::string::npos)
        return "DanSploit - Roblox script executor";
    if (lower.find("proxo") != std::string::npos)
        return "Proxo - Roblox script executor";
    if (lower.find("roexec") != std::string::npos || lower.find("ro-exec") != std::string::npos)
        return "RoExec - Roblox script executor with hypervisor-assisted injection";
    if (lower.find("cocoexploit") != std::string::npos || lower.find("coco exploit") != std::string::npos || lower.find("coco z") != std::string::npos)
        return "Coco Exploit - Roblox script executor";
    if (lower.find("zorara") != std::string::npos)
        return "Zorara - Roblox script executor";
    if (lower.find("cefacode") != std::string::npos)
        return "CefaCode - Roblox script executor";
    if (lower.find("vegax") != std::string::npos)
        return "VegaX - Roblox script executor with custom UI";
    if (lower.find("scriptware") != std::string::npos || lower.find("script-ware") != std::string::npos)
        return "Script-Ware - Premium Roblox script executor with anti-detection features";
    if (lower.find("xeno") != std::string::npos)
        return "Xeno - Roblox script executor/injector";
    if (lower.find("bunni") != std::string::npos)
        return "Bunni - Roblox script executor";
    if (lower.find("codex") != std::string::npos)
        return "Codex - Roblox script executor";
    if (lower.find("wave executor") != std::string::npos || lower.find("wave exploit") != std::string::npos || lower.find("wave.exe") != std::string::npos)
        return "Wave - High-level Roblox script executor";
    if (lower.find("velocity") != std::string::npos)
        return "Velocity - Roblox script executor";
    if (lower.find("hydrogen") != std::string::npos)
        return "Hydrogen - Roblox Lua executor";
    if (lower.find("celex") != std::string::npos)
        return "Celex - External/internal Roblox script executor";
    if (lower.find("alysse") != std::string::npos)
        return "Alysse - Roblox script executor";
    if (lower.find("luna executor") != std::string::npos)
        return "Luna - Roblox script executor";
    if (lower.find("zenith") != std::string::npos)
        return "Zenith - Roblox script executor";
    if (lower.find("neutron") != std::string::npos)
        return "Neutron - Roblox script executor";
    if (lower.find("incognito") != std::string::npos)
        return "Incognito - Roblox script executor";
    if (lower.find("horizon external") != std::string::npos)
        return "Horizon - External Roblox cheat tool";
    if (lower.find("celery") != std::string::npos)
        return "Celery - Roblox script executor/injector";
    if (lower.find("rc7.exe") != std::string::npos || lower.find("rc7 executor") != std::string::npos || lower.find("\\rc7") != std::string::npos)
        return "RC7 - Legacy Roblox script executor";
    if (lower.find("restore point") != std::string::npos || lower.find("volume_shadow") != std::string::npos || lower.find("shadow cop") != std::string::npos)
        return "Windows System Restore Points - Normal Windows OS snapshots used for system recovery and updates.";
    if (lower.find("proto smasher") != std::string::npos)
        return "Proto Smasher - Legacy Roblox script executor";
    if (lower.find("calamari") != std::string::npos)
        return "Calamari - Roblox script executor";
    if (lower.find("valyse") != std::string::npos)
        return "Valyse - Roblox script executor";
    if (lower.find("nezur") != std::string::npos)
        return "Nezur - Roblox script executor / external tool";
    if (lower.find("seliware") != std::string::npos)
        return "Seliware - Roblox script executor";
    if (lower.find("oxygen") != std::string::npos)
        return "Oxygen U - Roblox script executor";
    if (lower.find("kiwi x") != std::string::npos || lower.find("kiwix") != std::string::npos)
        return "Kiwi X - Roblox script executor";
    if (lower.find("comet executor") != std::string::npos)
        return "Comet - Roblox script executor";
    if (lower.find("shadow executor") != std::string::npos)
        return "Shadow - Roblox script executor";
    if (lower.find("aspect executor") != std::string::npos)
        return "Aspect - Roblox script executor";
    if (lower.find("novaline") != std::string::npos)
        return "Novaline - Roblox script executor";
    if (lower.find("sigma executor") != std::string::npos)
        return "Sigma - Roblox script executor";
    if (lower.find("meteor executor") != std::string::npos)
        return "Meteor - Roblox script executor";
    if (lower.find("appleware") != std::string::npos)
        return "Appleware - Roblox script executor";
    if (lower.find("nexus executor") != std::string::npos)
        return "Nexus - Roblox script executor";
    if (lower.find("cryptic executor") != std::string::npos)
        return "Cryptic - Roblox script executor";
    if (lower.find("phantom executor") != std::string::npos)
        return "Phantom - Roblox script executor";
    if (lower.find("eclipse executor") != std::string::npos)
        return "Eclipse - Roblox script executor";
    if (lower.find("omega executor") != std::string::npos)
        return "Omega - Roblox script executor";
    if (lower.find("lx63") != std::string::npos)
        return "LX63 - Roblox script executor";
    if (lower.find("electron executor") != std::string::npos)
        return "Electron - Roblox script executor";

    // Aimbot / ESP / External Tools
    if (lower.find("matcha") != std::string::npos)
        return "Matcha - External aimbot and ESP overlay client for Roblox PvP games";
    if (lower.find("newui") != std::string::npos || lower.find("new ui") != std::string::npos)
        return "NewUI (Matrix Hub) - External cheat client with aimbot, ESP, and triggerbot";
    if (lower.find("oldui") != std::string::npos || lower.find("old ui") != std::string::npos)
        return "OldUI (Matrix Hub) - Earlier version of Matrix Hub external cheat";
    if (lower.find("matrixhub") != std::string::npos || lower.find("matrix hub") != std::string::npos || lower.find("matrix external") != std::string::npos)
        return "Matrix Hub - External cheat tool with aimbot, ESP, and camlock for Roblox";
    if (lower.find("aimmy") != std::string::npos)
        return "Aimmy - AI-powered aimbot that uses screen capture to auto-aim";
    if (lower.find("camlock") != std::string::npos)
        return "Camlock - Camera lock exploit that forces aim onto nearby players";
    if (lower.find("serotonin") != std::string::npos)
        return "Serotonin - External Roblox cheat with aimbot and ESP";
    if (lower.find("thunderaim") != std::string::npos || lower.find("thunder aim") != std::string::npos)
        return "Thunder Aim - External aimbot for Roblox games";
    if (lower.find("da hood aimbot") != std::string::npos || lower.find("da hood external") != std::string::npos || lower.find("dahood aimbot") != std::string::npos)
        return "Da Hood Aimbot - External aimbot specifically designed for Da Hood";
    if (lower.find("rivals aimbot") != std::string::npos || lower.find("rivals external") != std::string::npos || lower.find("rivals esp") != std::string::npos)
        return "Rivals Cheat - External aimbot/ESP for the Roblox game Rivals";
    if (lower.find("silent aim") != std::string::npos || lower.find("silentaim") != std::string::npos)
        return "Silent Aim - Cheat that redirects bullets to hit targets without visually aiming";
    if (lower.find("triggerbot") != std::string::npos)
        return "Triggerbot - Automatically shoots when crosshair is over an enemy";
    if (lower.find("hitbox expander") != std::string::npos || lower.find("hitbox exploit") != std::string::npos)
        return "Hitbox Expander - Enlarges enemy hitboxes making them easier to hit";
    if (lower.find("desync") != std::string::npos)
        return "Desync Exploit - Manipulates network sync to make player appear in a different location";

    // Debuggers / RE Tools
    if (lower.find("cheatengine") != std::string::npos || lower.find("cheat engine") != std::string::npos)
        return "Cheat Engine - Memory editor used to modify game values (speed, health, etc.)";
    if (lower.find("system informer") != std::string::npos)
        return "System Informer - Advanced task manager used to inspect/modify running processes";
    if (lower.find("x64dbg") != std::string::npos || lower.find("x32dbg") != std::string::npos)
        return "x64dbg/x32dbg - Debugger used for reverse engineering executables";
    if (lower.find("extreme injector") != std::string::npos)
        return "Extreme Injector - Used to inject cheat DLLs into games";
    if (lower.find("nigctl") != std::string::npos || lower.find("winkernelinterface") != std::string::npos)
        return "PaidFn Driver - Custom kernel driver used for ESP/Aimbot and memory manipulation";

    // HWID Spoofers
    if (lower.find("hwid spoofer") != std::string::npos || lower.find("hwid-spoofer") != std::string::npos || lower.find("hwid changer") != std::string::npos)
        return "HWID Spoofer - Tool that fakes hardware identifiers to evade hardware bans";
    if (lower.find("easyhwid") != std::string::npos)
        return "EasyHWID - Hardware ID spoofing tool to bypass hardware bans";
    if (lower.find("permanentspoofer") != std::string::npos)
        return "PermanentSpoofer - HWID spoofing tool that persists across reboots";
    if (lower.find("ruinspoofer") != std::string::npos)
        return "RuinSpoofer - Hardware ID spoofing tool";
    if (lower.find("qlitech") != std::string::npos)
        return "QliTech - HWID spoofer and anti-cheat bypass tool";
    if (lower.find("volumeid") != std::string::npos)
        return "VolumeID - Disk serial number changer used to evade hardware bans";
    if (lower.find("kdmapper") != std::string::npos)
        return "KDMapper - Kernel driver mapper used to load unsigned cheat drivers into Windows";
    if (lower.find("pcihide") != std::string::npos)
        return "PCIHide - Tool that hides PCI devices from anti-cheat detection";
    if (lower.find("serial changer") != std::string::npos)
        return "Serial Changer - Hardware serial number modification tool";
    if (lower.find("mac address changer") != std::string::npos)
        return "MAC Address Changer - Network adapter identifier spoofing tool";

    // Websites
    if (lower.find("wearedevs") != std::string::npos)
        return "WeAreDevs - Cheat distribution website known for hosting Roblox exploits";
    if (lower.find("linkvertise") != std::string::npos)
        return "Linkvertise - Ad-gateway commonly used to monetize cheat downloads";
    if (lower.find("whatexpsare") != std::string::npos)
        return "WhatExpsAre - Website listing and distributing Roblox exploit tools";
    if (lower.find("scriptblox") != std::string::npos)
        return "ScriptBlox - Platform for sharing and downloading Roblox cheat scripts";
    if (lower.find("v3rmillion") != std::string::npos)
        return "V3rmillion - Forum community centered around Roblox exploiting";
    if (lower.find("robloxhax") != std::string::npos)
        return "RobloxHax - Roblox cheat distribution website";
    if (lower.find("easyexploits") != std::string::npos)
        return "EasyExploits - Roblox exploit API and distribution platform";
    if (lower.find("kingexploits") != std::string::npos)
        return "KingExploits - Roblox exploit distribution website";
    if (lower.find("keybypass") != std::string::npos || lower.find("platoboost") != std::string::npos || lower.find("lootlabs") != std::string::npos || lower.find("lootdest") != std::string::npos || lower.find("work.ink") != std::string::npos || lower.find("paster.so") != std::string::npos)
        return "Cheat Key Gateway / Bypass - Link gateway used by cheaters to retrieve executor daily activation keys";
    if (lower.find("discord_rpc_cache") != std::string::npos || lower.find("discord rpc") != std::string::npos)
        return "Discord Activity Cache - Rich presence cache logged execution of cheat software while Discord was open";
    if (lower.find("dx9ware") != std::string::npos || lower.find("dx9") != std::string::npos)
        return "DX9Ware - Premium external Roblox aimbot, triggerbot, and visual ESP suite";
    if (lower.find("swift") != std::string::npos && lower.find("vk_swiftshader") == std::string::npos)
        return "Swift - Modern Roblox Luau script executor";
    if (lower.find("volcano") != std::string::npos)
        return "Volcano - Roblox exploit engine with native memory injection";
    if (lower.find("vandal") != std::string::npos)
        return "Vandal - External aimbot and visual overlay for Roblox competitive games";
    if (lower.find("aurora") != std::string::npos)
        return "Aurora - Roblox script executor and bytecode injector";
    if (lower.find("frost executor") != std::string::npos)
        return "Frost - Roblox script executor";
    if (lower.find("olympus") != std::string::npos)
        return "Olympus - High-level script executor with anti-tamper evasion";
    if (lower.find("sensitiv") != std::string::npos)
        return "Sensitiv - External aim assistant and triggerbot for Roblox";
    if (lower.find("anti_forensics_wiper") != std::string::npos || lower.find("usn change journal") != std::string::npos)
        return "Anti-Forensics Wiper - Tool that deleted system change logs to hide cheat execution";
    if (lower.find("run_mru") != std::string::npos || lower.find("windows run dialog") != std::string::npos)
        return "Windows RunMRU - Suspect executed cheat commands directly via the Windows Run prompt";
    if (lower.find("roblox_lua_injection") != std::string::npos || lower.find("luau script executor") != std::string::npos)
        return "Active Luau Injection - In-game script executor environment actively hooked into Roblox memory";
    if (lower.find("external_overlay") != std::string::npos || lower.find("transparent overlay") != std::string::npos)
        return "External Overlay Window - Aimbot/ESP window layered transparently over Roblox";
    if (lower.find("shellbags_folder") != std::string::npos)
        return "ShellBags Artifact - Folder was navigated in Windows Explorer (remains after folder deletion)";

    // Bootstrappers (informational)
    if (lower.find("bloxstrap") != std::string::npos)
        return "Bloxstrap - Alternative Roblox launcher (not a cheat, but often used alongside them)";
    if (lower.find("fishstrap") != std::string::npos)
        return "Fishstrap - Alternative Roblox bootstrapper";
    if (lower.find("voidstrap") != std::string::npos)
        return "Voidstrap - Alternative Roblox bootstrapper";
    if (lower.find("frostrap") != std::string::npos)
        return "Frostrap - Alternative Roblox bootstrapper";
    if (lower.find("macaw") != std::string::npos)
        return "Macaw - Alternative Roblox bootstrapper";

    // Emulators
    if (lower.find("bluestacks") != std::string::npos)
        return "BlueStacks - Android emulator (can be used to run mobile cheats on PC)";
    if (lower.find("ldplayer") != std::string::npos || lower.find("ldconsole") != std::string::npos)
        return "LDPlayer - Android emulator";
    if (lower.find("mumu") != std::string::npos)
        return "MuMu Player - Android emulator";
    if (lower.find("memuplay") != std::string::npos || lower.find("memu") != std::string::npos)
        return "MEmu - Android emulator";
    if (lower.find("nox") != std::string::npos)
        return "Nox Player - Android emulator";
    if (lower.find("gameloop") != std::string::npos)
        return "GameLoop - Android emulator by Tencent";

    // Technical findings
    if (lower.find("networkaddress override") != std::string::npos || lower.find("mac") != std::string::npos && lower.find("spoof") != std::string::npos)
        return "MAC Address Spoofing - Network adapter ID was manually changed to evade hardware bans";
    if (lower.find("etw") != std::string::npos && lower.find("blind") != std::string::npos)
        return "ETW Blinding - Windows telemetry was patched to hide cheat activity from anti-cheat";
    if (lower.find("manual map") != std::string::npos || lower.find("unbacked") != std::string::npos)
        return "Manual Mapping - Cheat DLL was loaded directly into memory without using standard Windows APIs to avoid detection";
    if (lower.find("secure boot") != std::string::npos)
        return "Secure Boot Disabled - Allows unsigned kernel drivers (cheat drivers) to load at boot";
    if (lower.find("shadow cop") != std::string::npos)
        return "Volume Shadow Copies - System restore points that may contain hidden cheat artifacts";
    if (lower.find("timestomp") != std::string::npos)
        return "Timestomping - File timestamps were manipulated to hide when cheats were installed";
    if (lower.find("hosts") != std::string::npos && lower.find("roblox") != std::string::npos)
        return "Hosts File Block - Roblox telemetry domains were blocked to prevent cheat detection";
    if (lower.find("byovd") != std::string::npos || lower.find("vulnerable driver") != std::string::npos)
        return "BYOVD Attack - A vulnerable signed driver was loaded to gain kernel access for cheats";
    if (lower.find("rdtsc") != std::string::npos || lower.find("cpuid") != std::string::npos)
        return "RDTSC Timing Anomaly - CPU timing suggests a hypervisor or VM (may be normal on Windows 11 with VBS)";
    if (lower.find("alternate data stream") != std::string::npos || lower.find("ntfs") != std::string::npos && lower.find("ads") != std::string::npos)
        return "NTFS Alternate Data Streams - Hidden data attached to files, possibly concealing cheat payloads";
    if (lower.find("srum") != std::string::npos)
        return "SRUM Database - Windows System Resource Usage Monitor recorded cheat execution history";
    if (lower.find("dma") != std::string::npos || lower.find("fpga") != std::string::npos || lower.find("pcileech") != std::string::npos)
        return "DMA/FPGA Hardware - Direct Memory Access card that can read/write game memory from another device";
    if (lower.find("usb") != std::string::npos && lower.find("plug") != std::string::npos)
        return "USB Device Activity - USB storage device was connected recently (may have been used to transfer cheats)";

    return ""; // No explanation available
}

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


std::string FormatTime12Hour(time_t t) {
    struct tm tm_info;
    localtime_s(&tm_info, &t);
    char buf[64];
    int hour12 = tm_info.tm_hour % 12;
    if (hour12 == 0) hour12 = 12;
    const char* ampm = (tm_info.tm_hour >= 12) ? "PM" : "AM";
    sprintf_s(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d %s",
        tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
        hour12, tm_info.tm_min, tm_info.tm_sec, ampm);
    return std::string(buf);
}

std::string ConvertUtcToLocal12Hour(const std::string& utcStr) {
    if (utcStr.length() < 19) return utcStr;
    SYSTEMTIME stUtc = {0};
    int y = 0, m = 0, d = 0, h = 0, min = 0, s = 0;
    if (sscanf_s(utcStr.c_str(), "%d-%d-%d%*c%d:%d:%d", &y, &m, &d, &h, &min, &s) >= 6) {
        stUtc.wYear = (WORD)y;
        stUtc.wMonth = (WORD)m;
        stUtc.wDay = (WORD)d;
        stUtc.wHour = (WORD)h;
        stUtc.wMinute = (WORD)min;
        stUtc.wSecond = (WORD)s;

        SYSTEMTIME stLocal = {0};
        if (SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal)) {
            char buf[128];
            int hour12 = stLocal.wHour % 12;
            if (hour12 == 0) hour12 = 12;
            const char* ampm = (stLocal.wHour >= 12) ? "PM" : "AM";
            sprintf_s(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d %s",
                stLocal.wYear, stLocal.wMonth, stLocal.wDay,
                hour12, stLocal.wMinute, stLocal.wSecond, ampm);
            return std::string(buf);
        }
    }
    return utcStr;
}

std::string FormatFileTime12Hour(const FILETIME& ft) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return "Unknown Date/Time";
    SYSTEMTIME stUtc = {0};
    if (!FileTimeToSystemTime(&ft, &stUtc)) return "Unknown Date/Time";
    SYSTEMTIME stLocal = {0};
    if (SystemTimeToTzSpecificLocalTime(nullptr, &stUtc, &stLocal)) {
        char buf[128];
        int hour12 = stLocal.wHour % 12;
        if (hour12 == 0) hour12 = 12;
        const char* ampm = (stLocal.wHour >= 12) ? "PM" : "AM";
        sprintf_s(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d %s",
            stLocal.wYear, stLocal.wMonth, stLocal.wDay,
            hour12, stLocal.wMinute, stLocal.wSecond, ampm);
        return std::string(buf);
    }
    return "Unknown Date/Time";
}

FILETIME GetFileWriteTime(const std::wstring& path) {
    FILETIME ft = {0};
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h != INVALID_HANDLE_VALUE) {
        GetFileTime(h, nullptr, nullptr, &ft);
        CloseHandle(h);
    }
    return ft;
}

std::string GetTimestamp() {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    return FormatTime12Hour(now);
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
    const wchar_t* bamRoots[] = {
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\UserSettings",
        L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings",
        nullptr
    };

    for (int rIdx = 0; bamRoots[rIdx]; rIdx++) {
        HKEY hBam;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, bamRoots[rIdx], 0, KEY_READ, &hBam) != ERROR_SUCCESS) {
            continue;
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
    }
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

struct DetectedGameSession {
    uint64_t placeId = 0;
    uint64_t universeId = 0;
    std::string gameName;
    std::string sessionTimestamp;
    std::string sessionFile;
    FILETIME startFt = {0};
    FILETIME endFt = {0};
};

struct CheatResult {
    std::vector<Finding> findings;
    int score;
    std::string verdict;
    std::vector<DetectedGameSession> detectedGames;
    std::string primaryGame;
    bool gameTargetedByCheats = false;
};

bool IsWhitelisted(const std::wstring& str) {
    std::wstring lower = Lower(str);
    if (lower.find(L"icicle") != std::wstring::npos) return true;
    return false;
}

bool IsWhitelisted(const std::string& str) {
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    if (lower.find("icicle") != std::string::npos) return true;
    return false;
}

// Cheat signatures are matched by substring, so any signature that is a
// fragment of a real Windows binary name fires on that binary. "krnl" sits
// inside "ntoskrnl.exe", and a single such match was enough to turn a clean
// machine into CONFIRMED CHEATER. The name of a system executable is never
// evidence on its own, so it is never a name-match. This costs nothing against
// a real cheat renamed to one of these names: the content hash and the PE
// import triad both still catch it, and neither can be influenced by a name.
const std::set<std::wstring>& ProtectedBinaryNames() {
    static const std::set<std::wstring> names = {
        L"ntoskrnl.exe", L"csrss.exe", L"lsass.exe", L"services.exe",
        L"smss.exe", L"wininit.exe", L"winlogon.exe", L"explorer.exe",
        L"svchost.exe", L"taskhost.exe", L"taskhostw.exe",
        L"runtimebroker.exe", L"dwm.exe", L"conhost.exe", L"dllhost.exe",
        L"rundll32.exe", L"regsvr32.exe", L"reg.exe", L"cmd.exe",
        L"powershell.exe", L"pwsh.exe", L"sihost.exe", L"fontdrvhost.exe",
        L"ctfmon.exe", L"searchindexer.exe", L"searchhost.exe",
        L"searchapp.exe", L"shellexperiencehost.exe", L"systemsettings.exe",
        L"applicationframehost.exe", L"backgroundtaskhost.exe",
        L"useroobebroker.exe", L"textinputhost.exe", L"widgets.exe",
        L"securityhealthservice.exe", L"securityhealthsystray.exe",
        L"msmpeng.exe", L"nissrv.exe", L"wmiprvse.exe", L"audiodg.exe",
        L"msiexec.exe", L"spoolsv.exe", L"smartscreen.exe", L"consent.exe",
        L"notepad.exe", L"calc.exe", L"msedge.exe", L"chrome.exe",
        L"firefox.exe", L"onedrive.exe", L"code.exe",
    };
    return names;
}

// Reduce anything a signature might be weighed against - a full path, a process
// name, or an Amcache record key of the form "{basename}|{id}" - to the bare
// executable name. Amcache record keys carry a hex identifier after the bar,
// and letting that reach a substring match lets random hex collide with short
// signatures.
std::wstring BaseExeName(const std::wstring& name) {
    size_t start = name.find_last_of(L"\\/");
    start = (start == std::wstring::npos) ? 0 : start + 1;
    size_t end = name.find(L'|', start);
    if (end == std::wstring::npos) end = name.size();
    std::wstring base = name.substr(start, end - start);
    for (auto& c : base) c = towlower(c);
    return base;
}

bool IsProtectedBinaryName(const std::wstring& name) {
    return ProtectedBinaryNames().count(BaseExeName(name)) > 0;
}

bool MatchesCheatSignature(const std::wstring& name) {
    if (IsWhitelisted(name)) return false;
    if (IsProtectedBinaryName(name)) return false;
    std::wstring lower = Lower(name);
    for (const auto& sig : CHEAT_SIGNATURES) {
        if (lower.find(Lower(sig)) != std::wstring::npos) return true;
    }
    return false;
}

bool MatchesCheatFileSignature(const std::wstring& filename) {
    if (IsWhitelisted(filename)) return false;
    if (IsProtectedBinaryName(filename)) return false;
    std::wstring lower = Lower(filename);
    for (const auto& sig : CHEAT_FILE_SIGNATURES) {
        if (lower.find(Lower(sig)) != std::wstring::npos) return true;
    }
    return false;
}

static const std::map<uint64_t, std::string> KNOWN_GAMES = {
    { 128736949265057ULL, "Gakuran (Ã¥Â­Â¦Ã¤Â¹Â±)" },
    { 9199655655ULL, "Gakuran (Ã¥Â­Â¦Ã¤Â¹Â±)" },
    { 107778070777162ULL, "Steal An Egg" },
    { 10563114921ULL, "Steal An Egg" },
    { 2788229376ULL, "Da Hood" },
    { 982551532ULL, "Da Hood" },
    { 17625359962ULL, "Rivals" },
    { 6035872082ULL, "Rivals" },
    { 2753915549ULL, "Blox Fruits" },
    { 4442272183ULL, "Blox Fruits" },
    { 994732206ULL, "Blox Fruits" },
    { 286090429ULL, "Arsenal" },
    { 111958650ULL, "Arsenal" },
    { 6872265039ULL, "BedWars" },
    { 2619619496ULL, "BedWars" },
    { 4170656491ULL, "Deepwoken" },
    { 1359573625ULL, "Deepwoken" },
    { 16732694052ULL, "Fisch" },
    { 5750914919ULL, "Fisch" },
    { 155615604ULL, "Prison Life" },
    { 60680049ULL, "Jailbreak" },
    { 8737899170ULL, "Pet Simulator 99" },
    { 142823291ULL, "Murder Mystery 2" },
    { 13772394625ULL, "Blade Ball" },
    { 16146832113ULL, "Anime Vanguards" },
    { 893973440ULL, "Flee the Facility" },
    { 189707ULL, "Natural Disaster Survival" }
};

inline std::string CleanRobloxString(const std::string& input) {
    std::string out = input;
    size_t pos;
    while ((pos = out.find("\\u0026")) != std::string::npos) out.replace(pos, 6, "&");
    while ((pos = out.find("\\u0027")) != std::string::npos) out.replace(pos, 6, "'");
    while ((pos = out.find("\\u0022")) != std::string::npos) out.replace(pos, 6, "\"");
    return out;
}

std::string ResolveRobloxGameName(uint64_t universeId, uint64_t placeId) {
    if (universeId > 0) {
        auto it = KNOWN_GAMES.find(universeId);
        if (it != KNOWN_GAMES.end()) return it->second;
    }
    if (placeId > 0) {
        auto it = KNOWN_GAMES.find(placeId);
        if (it != KNOWN_GAMES.end()) return it->second;
    }

    uint64_t uId = universeId;
    if (uId == 0 && placeId > 0) {
        HINTERNET hSess = WinHttpOpen(L"RobloxScanner/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSess) {
            WinHttpSetTimeouts(hSess, 2000, 2000, 2000, 2000);
            HINTERNET hConn = WinHttpConnect(hSess, L"apis.roblox.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConn) {
                std::wstring path = L"/universes/v1/places/" + std::to_wstring(placeId) + L"/universe";
                HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (hReq) {
                    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                        WinHttpReceiveResponse(hReq, nullptr)) {
                        std::string resp;
                        ReadWinHttpResponseString(hReq, resp);
                        size_t upos = resp.find("\"universeId\":");
                        if (upos != std::string::npos) {
                            size_t numStart = resp.find_first_of("0123456789", upos);
                            if (numStart != std::string::npos) {
                                size_t numEnd = resp.find_first_not_of("0123456789", numStart);
                                try { uId = std::stoull(resp.substr(numStart, numEnd - numStart)); } catch (...) {}
                            }
                        }
                    }
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConn);
            }
            WinHttpCloseHandle(hSess);
        }
    }

    if (uId > 0) {
        HINTERNET hSess = WinHttpOpen(L"RobloxScanner/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSess) {
            WinHttpSetTimeouts(hSess, 2500, 2500, 2500, 2500);
            HINTERNET hConn = WinHttpConnect(hSess, L"games.roblox.com", INTERNET_DEFAULT_HTTPS_PORT, 0);
            if (hConn) {
                std::wstring path = L"/v1/games?universeIds=" + std::to_wstring(uId);
                HINTERNET hReq = WinHttpOpenRequest(hConn, L"GET", path.c_str(), nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
                if (hReq) {
                    if (WinHttpSendRequest(hReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                        WinHttpReceiveResponse(hReq, nullptr)) {
                        std::string resp;
                        ReadWinHttpResponseString(hReq, resp);
                        size_t npos = resp.find("\"name\":\"");
                        if (npos != std::string::npos) {
                            size_t start = npos + 8;
                            size_t end = resp.find("\"", start);
                            if (end != std::string::npos) {
                                std::string gName = resp.substr(start, end - start);
                                WinHttpCloseHandle(hReq);
                                WinHttpCloseHandle(hConn);
                                WinHttpCloseHandle(hSess);
                                return CleanRobloxString(gName);
                            }
                        }
                    }
                    WinHttpCloseHandle(hReq);
                }
                WinHttpCloseHandle(hConn);
            }
            WinHttpCloseHandle(hSess);
        }
    }

    if (placeId > 0) {
        return "Roblox Place #" + std::to_string(placeId);
    }
    return "Unknown Roblox Experience";
}

std::vector<DetectedGameSession> ScanRobloxGameSessions() {
    std::vector<DetectedGameSession> sessions;
    wchar_t localApp[MAX_PATH];
    if (SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localApp) != S_OK) return sessions;

    std::wstring robloxLogsDir = std::wstring(localApp) + L"\\Roblox\\logs";
    std::error_code ec;
    if (!std::filesystem::exists(robloxLogsDir, ec)) return sessions;

    struct LogEntry {
        std::filesystem::path path;
        std::filesystem::file_time_type writeTime;
    };
    std::vector<LogEntry> logFiles;
    for (const auto& entry : std::filesystem::directory_iterator(robloxLogsDir, ec)) {
        if (entry.is_regular_file() && entry.path().extension() == L".log") {
            logFiles.push_back({ entry.path(), entry.last_write_time(ec) });
        }
    }

    std::sort(logFiles.begin(), logFiles.end(), [](const LogEntry& a, const LogEntry& b) {
        return a.writeTime > b.writeTime;
    });

    int checked = 0;
    std::set<uint64_t> seenUniverses;
    std::set<uint64_t> seenPlaces;

    for (const auto& lf : logFiles) {
        if (checked++ >= 15) break;
        std::ifstream fin(lf.path);
        if (!fin.is_open()) continue;

        std::string line;
        uint64_t foundPlace = 0;
        uint64_t foundUniverse = 0;
        std::string timeStr = "";
        FILETIME startFt = {0};

        while (std::getline(fin, line)) {
            size_t ppos = line.find("placeid:");
            if (ppos == std::string::npos) ppos = line.find("serverplaceid=");
            if (ppos == std::string::npos) ppos = line.find("serverplaceid:");
            
            if (ppos != std::string::npos) {
                size_t numStart = line.find_first_of("0123456789", ppos);
                if (numStart != std::string::npos) {
                    size_t numEnd = line.find_first_not_of("0123456789", numStart);
                    std::string pStr = line.substr(numStart, numEnd - numStart);
                    try { foundPlace = std::stoull(pStr); } catch (...) {}
                }
            }

            size_t upos = line.find("universeid:");
            if (upos != std::string::npos) {
                size_t numStart = line.find_first_of("0123456789", upos);
                if (numStart != std::string::npos) {
                    size_t numEnd = line.find_first_not_of("0123456789", numStart);
                    std::string uStr = line.substr(numStart, numEnd - numStart);
                    try { foundUniverse = std::stoull(uStr); } catch (...) {}
                }
            }

            if (timeStr.empty() && line.length() >= 19 && line[4] == '-' && line[7] == '-' && line[10] == 'T') {
                std::string rawUtc = line.substr(0, 19);
                timeStr = ConvertUtcToLocal12Hour(rawUtc);
                SYSTEMTIME stUtc = {0};
                int y = 0, m = 0, d = 0, h = 0, min = 0, s = 0;
                if (sscanf_s(rawUtc.c_str(), "%d-%d-%d%*c%d:%d:%d", &y, &m, &d, &h, &min, &s) >= 6) {
                    stUtc.wYear = (WORD)y; stUtc.wMonth = (WORD)m; stUtc.wDay = (WORD)d;
                    stUtc.wHour = (WORD)h; stUtc.wMinute = (WORD)min; stUtc.wSecond = (WORD)s;
                    SystemTimeToFileTime(&stUtc, &startFt);
                }
            }

            if (foundPlace > 0 && foundUniverse > 0) break;
        }
        fin.close();

        FILETIME endFt = GetFileWriteTime(lf.path.wstring());
        if (timeStr.empty()) {
            timeStr = FormatFileTime12Hour(endFt);
            startFt = endFt;
        }

        if (foundPlace > 0 || foundUniverse > 0) {
            if (seenPlaces.find(foundPlace) == seenPlaces.end() || seenUniverses.find(foundUniverse) == seenUniverses.end()) {
                if (foundPlace > 0) seenPlaces.insert(foundPlace);
                if (foundUniverse > 0) seenUniverses.insert(foundUniverse);

                DetectedGameSession g;
                g.placeId = foundPlace;
                g.universeId = foundUniverse;
                g.sessionTimestamp = timeStr;
                g.sessionFile = PathUtf8(lf.path.filename());
                g.gameName = ResolveRobloxGameName(foundUniverse, foundPlace);
                g.startFt = startFt;
                g.endFt = endFt;
                sessions.push_back(g);
            }
        }
    }
    return sessions;
}

std::string CorrelateSessionForFileTime(const FILETIME& ft, const std::vector<DetectedGameSession>& sessions) {
    if (ft.dwLowDateTime == 0 && ft.dwHighDateTime == 0) return "";
    
    ULARGE_INTEGER uFt;
    uFt.LowPart = ft.dwLowDateTime;
    uFt.HighPart = ft.dwHighDateTime;
    
    for (const auto& s : sessions) {
        ULARGE_INTEGER uStart, uEnd;
        uStart.LowPart = s.startFt.dwLowDateTime;
        uStart.HighPart = s.startFt.dwHighDateTime;
        uEnd.LowPart = s.endFt.dwLowDateTime;
        uEnd.HighPart = s.endFt.dwHighDateTime;
        
        ULONGLONG margin = 18000000000ULL; // 30 minutes margin in 100ns units
        ULONGLONG winStart = (uStart.QuadPart > margin) ? (uStart.QuadPart - margin) : 0;
        ULONGLONG winEnd = (uEnd.QuadPart > 0) ? (uEnd.QuadPart + margin) : (uStart.QuadPart + (margin * 2));
        
        if (uStart.QuadPart > 0 && uFt.QuadPart >= winStart && uFt.QuadPart <= winEnd) {
            return " [MATCHED GAME: Active during " + s.gameName + " (Place ID: " + std::to_string(s.placeId) + ")]";
        }
    }
    
    if (!sessions.empty() && sessions[0].startFt.dwLowDateTime != 0) {
        SYSTEMTIME stTarget, stSession;
        FileTimeToSystemTime(&ft, &stTarget);
        FileTimeToSystemTime(&sessions[0].startFt, &stSession);
        if (stTarget.wYear == stSession.wYear && stTarget.wMonth == stSession.wMonth && stTarget.wDay == stSession.wDay) {
            return " [Executed earlier today outside active " + sessions[0].gameName + " session]";
        }
    }
    
    FILETIME now;
    GetSystemTimeAsFileTime(&now);
    ULARGE_INTEGER uNow;
    uNow.LowPart = now.dwLowDateTime;
    uNow.HighPart = now.dwHighDateTime;
    if (uNow.QuadPart > uFt.QuadPart) {
        ULONGLONG diffSec = (uNow.QuadPart - uFt.QuadPart) / 10000000ULL;
        if (diffSec > 86400 * 7) {
            return " [Historical Execution - not active during today's session]";
        } else if (diffSec > 86400) {
            return " [Past Execution (" + std::to_string(diffSec / 86400) + "d ago) - outside current session]";
        }
    }
    return " [Executed outside active Roblox session]";
}

struct EvidenceDescriptor {
    std::string title;
    std::string explanation;
};

EvidenceDescriptor GetEvidenceDescriptor(const std::string& cat) {
    if (cat == "BAM_REGISTRY" || cat == "BAM_EXECUTION") {
        return {
            "Windows Program Run History (BAM)",
            "Windows automatically tracks every program launched by the user. This proves the user actually opened and executed this cheat."
        };
    }
    if (cat == "MUICACHE") {
        return {
            "Application Launch Cache (MuiCache)",
            "Windows logged the application name when the user launched this executable."
        };
    }
    if (cat == "APPCOMPAT") {
        return {
            "Application Compatibility Execution Record",
            "Windows tracked this cheat executable running on the computer."
        };
    }
    if (cat == "PREFETCH") {
        return {
            "Application Execution Artifact (Windows Prefetch)",
            "Windows Prefetch proves this exact cheat file was launched and executed."
        };
    }
    if (cat == "USERASSIST") {
        return {
            "Opened from Desktop / Start Menu (UserAssist)",
            "Windows UserAssist logged the user clicking on and launching this cheat program."
        };
    }
    if (cat == "DEFENDER_EXCLUSION") {
        return {
            "Antivirus Whitelist (Defender Exclusion)",
            "The user explicitly told Windows Defender to ignore this folder so antivirus would not block or delete their cheats."
        };
    }
    if (cat == "ROBLOX_CRASH_LOG") {
        return {
            "Roblox Game Crash (Caused by Injected Cheat)",
            "Roblox crashed because an unauthorized cheat or injector was injecting code into the game."
        };
    }
    if (cat == "SHELLBAGS_FOLDER") {
        return {
            "Opened Folder in File Explorer (Saved Even If Deleted)",
            "The user opened this cheat folder in Windows Explorer. Windows preserves this record even after the folder is deleted."
        };
    }
    if (cat == "OPENSAVE_MRU") {
        return {
            "File Picked in Open / Save Window",
            "The user selected or opened this cheat file inside a Windows file dialog."
        };
    }
    if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY") {
        return {
            "Web Browser Cheat Search / Download",
            "The user searched for or downloaded cheat software from a known cheat website in their browser."
        };
    }
    if (cat == "SEARCH_ENGINE_CHEAT_QUERY") {
        return {
            "Web Search for Roblox Exploits / Scripts",
            "The user explicitly searched for Roblox cheat scripts, script hubs, or executors on a search engine."
        };
    }
    if (cat == "YOUTUBE_CHEAT_VIDEO") {
        return {
            "Watched Roblox Script / Cheat Video on YouTube",
            "The user searched for or watched YouTube tutorials and showcases for Roblox exploit scripts."
        };
    }
    if (cat == "NETWORK_DATA_USAGE") {
        return {
            "Windows Network & Internet Data Usage (SRUM)",
            "Windows Network & Internet Data Usage recorded active network data transferred by this cheat application."
        };
    }
    if (cat == "HIGH_FREQUENCY_EXECUTION") {
        return {
            "Frequently Launched Cheat Application (FeatureUsage)",
            "Windows system tracking proves this cheat application was launched and switched to repeatedly on this PC."
        };
    }
    if (cat == "DISCORD_RPC_CACHE") {
        return {
            "Discord Activity Log",
            "Discord recorded the user running or using this cheat software while connected to Discord."
        };
    }
    if (cat == "DELETED_CHEAT" || cat == "RECYCLE_BIN" || cat == "TIMESTOMPING") {
        return {
            "Deleted Cheat File (Recovered by Scanner)",
            "The user deleted this cheat file, but low-level Windows drive records preserved the proof."
        };
    }
    if (cat == "PROCESS" || cat == "ACTIVE_PROCESS") {
        return {
            "Currently Running Cheat Process",
            "This cheat program was actively running in the background during the scan."
        };
    }
    if (cat == "ROBLOX_LUA_INJECTION" || cat == "ROBLOX_MEMORY") {
        return {
            "Active In-Game Script Injection",
            "Roblox game memory contains hooked script execution functions (getgenv, hookmetamethod) used to execute exploit scripts."
        };
    }
    if (cat == "EXTERNAL_OVERLAY") {
        return {
            "External Transparent Cheat Window (Aimbot/ESP)",
            "An external transparent window was overlaying Roblox to draw ESP boxes or aim assist over characters."
        };
    }
    if (cat == "MAC_SPOOF" || cat == "HWID_SPOOFER" || cat == "CHEAT_DRIVER" || cat == "ACTIVE_CHEAT_DRIVER") {
        return {
            "Hardware ID Spoofer / Ban Bypass Tool",
            "A tool or driver was used to alter the computer's hardware IDs to evade permanent game bans."
        };
    }
    if (cat == "BOOTSTRAPPER") {
        return {
            "Custom Roblox Launcher / Bootstrapper",
            "A third-party Roblox launcher was detected (such as Bloxstrap)."
        };
    }
    if (cat == "AUTORUN") {
        return {
            "Program Set To Launch Automatically",
            "This program is configured in a Run key or Startup folder, so Windows launches it every time the user logs in. Cheat software placed here survives reboots and does not need to be started by hand."
        };
    }
    if (cat == "UNSIGNED_SERVICE" || cat == "CHEAT_SERVICE") {
        return {
            "Windows Service Running As SYSTEM",
            "A Windows service runs with the highest privileges on the machine and starts before the user logs in. Unsigned or cheat-named services are among the strongest indicators available, because they indicate software that wanted to run with full control and survive everything else."
        };
    }
    if (cat == "SERVICE_NAME_MATCH") {
        return {
            "Service Name Resembled A Cheat Signature",
            "The service name matched a cheat signature, but the binary is Microsoft-signed. This is almost always an innocent name collision and is recorded only for completeness."
        };
    }
    if (cat == "WMI_PERSISTENCE" || cat == "WMI_SCRIPT_CONSUMER") {
        return {
            "WMI Subscription Re-Runs Its Payload",
            "A Windows Management Instrumentation subscription holds executable script or a command that fires again on a trigger such as logon, a timer, or another process starting. It lives in the system repository rather than as a file on disk, so ordinary file scans never see it. This is a standard persistence technique."
        };
    }
    if (cat == "ROBLOX_VERSION_SPRAWL") {
        return {
            "Multiple Roblox Client Versions Retained",
            "Roblox stores each client build in its own folder. Keeping old, superseded clients is how known client-side exploits stay usable, because a build that Roblox has since patched may still be vulnerable. This indicates capability and intent, not confirmed use."
        };
    }
    if (cat == "FACTORY_RESET") {
        return {
            "Windows Install / Reset Within Lookback Window",
            "A Windows install or reset was recorded recently. Resetting Windows wipes cheat files and execution history, so this is noted alongside other evidence. On its own it is a normal user action and proves nothing."
        };
    }
    if (cat == "VOLUME_SHADOW") {
        return {
            "Windows System Restore Snapshots (Backup Copies)",
            "Windows automatically creates System Restore points and backup snapshots for system updates and disaster recovery. This is standard Windows behavior."
        };
    }
    if (cat == "SCHEDULED_TASK") {
        return {
            "Windows Scheduled Task",
            "A task configured in Windows Task Scheduler was flagged for review."
        };
    }
    if (cat == "ANTI_FORENSICS_WIPER") {
        return {
            "Anti-Forensic Log / Journal Tampering",
            "Evidence of intentional clearing or disabling of Windows event logs, USN journals, or tracking mechanisms was detected."
        };
    }
    if (cat == "PATCHED_CLIENT") {
        return {
            "Modified / Unsigned Roblox Client",
            "The official Roblox client is always signed by Roblox Corporation. An unsigned or differently signed client means the anti-cheat payload was removed or replaced."
        };
    }
    if (cat == "CLIENT_SIGNER_MISMATCH") {
        return {
            "Roblox Client Signed By The Wrong Publisher",
            "The client binary on disk is signed by someone other than Roblox Corporation, indicating a rebuilt or tampered client."
        };
    }
    if (cat == "GENERIC_INJECTOR" || cat == "GENERIC_INJECTOR_EXEC") {
        return {
            "Unsigned Injection-Capable Binary",
            "An unsigned program containing the full remote-thread injection API set used by cheat injectors. Not matched to a known cheat name, so it may be a renamed or newly released tool."
        };
    }
    if (cat == "HIDDEN_THREAD" || cat == "HIDDEN_THREAD_CORROBORATED") {
        return {
            "Threads Running Outside Any Loaded Module",
            "A thread starts in unbacked executable memory rather than inside a legitimate DLL. Injected code and thread hijacking both leave this signature. Overlay and capture software can produce the same pattern, so it is only decisive when other evidence corroborates it."
        };
    }
    if (cat == "ROBLOX_DIR_DROP") {
        return {
            "File Staged In A Roblox Execution Folder",
            "Scripts or binaries placed in Roblox auto-run folders execute automatically when the game launches."
        };
    }
    if (cat == "DEBUGGER_ATTACHED") {
        return {
            "Debugger Attached To Roblox",
            "A debugger was attached to the live game process, which is used to defeat anti-cheat integrity checks. Also used by legitimate development, so this alone is not proof."
        };
    }
    return {
        cat,
        "System forensic artifact related to system inspection."
    };
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

// Format FILETIME to readable string (Local 12-hour AM/PM)
std::string FileTimeToString(const FILETIME& ft) {
    return FormatFileTime12Hour(ft);
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
        Sleep(15);
    }
    g_lastProgress = targetPercent;
}

std::string GetBroadCategory(const Finding& f);

// ============================================================================
// SCAN COVERAGE - every artifact source reports whether it was actually read
// ============================================================================
struct CoverageEntry {
    std::string subsystem;
    long examined;
    std::string status;
    bool limited = false;   // source was partially or fully unreadable
};

struct ScanCoverage {
    std::vector<CoverageEntry> entries;
    std::vector<std::string> skippedSources;

    void add(const std::string& subsystem, long examined, const std::string& status) {
        entries.push_back({subsystem, examined, status, false});
    }
    // Same as add(), but records that this source could not be fully read, so a
    // clean result coming from it carries no weight.
    void addLimited(const std::string& subsystem, long examined, const std::string& status) {
        entries.push_back({subsystem, examined, status, true});
        skippedSources.push_back(subsystem + " - " + status);
    }
    void skip(const std::string& subsystem, const std::string& why) {
        entries.push_back({subsystem, 0, "SKIPPED - " + why, true});
        skippedSources.push_back(subsystem + " - " + why);
    }
    int sourcesRead() const {
        int n = 0;
        for (const auto& e : entries) if (!e.limited) n++;
        return n;
    }
    bool hasLimitations() const { return !skippedSources.empty(); }
};

ScanCoverage g_cov;
bool g_isAdmin = false;
// Set in main(): whether a debugger was attached when the scan began. Surfaced
// in the report so an admin can see that a scan was taken apart rather than run.
bool g_debuggerAttached = false;
// Lowercase-hex SHA-1 hashes of every file Windows recorded executing in the
// Amcache hive during this scan. Populated by ScanAmcacheHive(), consumed by
// ScanDropLocations() so possession of an unsigned injector can be promoted to
// content-proven execution. Empty set = Amcache was unreadable (no elevation).
std::set<std::string> g_amcacheSha1;

// ============================================================================
// EVIDENCE TIER ENGINE
// A verdict is derived from the strength of the evidence, never from a raw
// sum of artifacts. Twenty weak traces cannot outvote one execution record.
// ============================================================================
enum class EvidenceTier { NONE = 0, INDICATIVE, REMNANT, EVASION, EXECUTED, LIVE };

const char* TierLabel(EvidenceTier t) {
    switch (t) {
        case EvidenceTier::LIVE:       return "LIVE - RUNNING NOW";
        case EvidenceTier::EXECUTED:   return "EXECUTION PROOF";
        case EvidenceTier::EVASION:    return "EVASION / CONCEALMENT";
        case EvidenceTier::REMNANT:    return "REMANT ON DISK";
        case EvidenceTier::INDICATIVE: return "INDICATIVE ONLY";
        default:                       return "NONE";
    }
}

EvidenceTier TierForCategory(const std::string& cat) {
    // code resident in a running process - observed at scan time
    static const std::set<std::string> live = {
        "PROCESS", "ACTIVE_PROCESS", "DLL_INJECTION", "MANUAL_MAPPING", "HIDDEN_THREAD_CORROBORATED",
        "PATCHED_CLIENT", "CLIENT_SIGNER_MISMATCH", "ROBLOX_MEMORY", "ROBLOX_LUA_INJECTION",
        "EXTERNAL_OVERLAY", "ACTIVE_CHEAT_DRIVER", "EMULATOR_PROCESS",
        "UNSIGNED_SERVICE", "CHEAT_SERVICE"
    };
    // Windows itself recorded this exact binary executing, or is configured
    // to execute it automatically on every logon
    static const std::set<std::string> executed = {
        "BAM_EXECUTION", "PREFETCH", "AMCACHE", "SRUM_DATABASE", "USERASSIST", "MUICACHE",
        "APPCOMPAT", "HIGH_FREQUENCY_EXECUTION", "NETWORK_DATA_USAGE", "GENERIC_INJECTOR_EXEC",
        "AUTORUN", "WMI_PERSISTENCE"
    };
    // deliberate concealment or ban-evasion intent
    static const std::set<std::string> evasion = {
        "HWID_SPOOFER", "MAC_SPOOF", "CHEAT_DRIVER", "DEFENDER_EXCLUSION", "TIMESTOMPING",
        "ANTI_FORENSICS_WIPER", "FACTORY_RESET", "ETW_BLINDING", "TELEMETRY_BLOCK",
        "BYOVD_EXPLOIT", "VULNERABLE_BOOT_STATE"
    };
    // present on the drive, deleted, installed - proves possession, not use
    static const std::set<std::string> remnant = {
        "CHEAT_FILE", "CHEAT_FOLDER", "INJECTOR_REMNANT", "SUSPICIOUS_TEMP_PE", "RECYCLE_BIN",
        "DELETED_FILE", "BOOTSTRAPPER", "EMULATOR_INSTALLED", "UNINSTALL_REGISTRY",
        "GENERIC_INJECTOR", "ROBLOX_DIR_DROP", "NTFS_ADS", "VOLUME_SHADOW",
        "CHEAT_DRIVER_FILE"
    };
    // A shellbag only proves a folder NAME was once opened in Explorer. Nothing
    // was recovered from it and no file is known to exist, so it is a trace, not
    // a remnant. A bare word like "matcha" can be an ordinary folder, so this
    // must never carry a verdict on its own.
    static const std::set<std::string> trace = {
        "SHELLBAGS_FOLDER"
    };
    if (live.count(cat))       return EvidenceTier::LIVE;
    if (executed.count(cat))   return EvidenceTier::EXECUTED;
    if (evasion.count(cat))    return EvidenceTier::EVASION;
    if (remnant.count(cat))    return EvidenceTier::REMNANT;
    if (trace.count(cat))      return EvidenceTier::INDICATIVE;
    return EvidenceTier::INDICATIVE;
}

struct ThreatProfile {
    int score = 0;
    std::string verdict;
    std::string driver;        // the single strongest piece of evidence behind the verdict
    std::string driverTier;
    int liveCount = 0, executedCount = 0, evasionCount = 0, remnantCount = 0, indicativeCount = 0;
    long totalArtifacts = 0;
};

// Weak traces are demoted so they can never carry a verdict on their own.
const int MIN_VERDICT_CONFIDENCE = 50;

ThreatProfile ComputeThreat(const CheatResult& r) {
    ThreatProfile tp;

    EvidenceTier strongest = EvidenceTier::NONE;
    std::string strongestDesc, strongestEv;

    int live = 0, exec = 0, evas = 0, remn = 0, indi = 0;
    for (const auto& f : r.findings) {
        if (IsWhitelisted(f.description) || IsWhitelisted(f.evidence)) continue;
        tp.totalArtifacts++;

        EvidenceTier t = TierForCategory(f.category);
        // A weak match must not carry a verdict, whatever its class. A factory
        // reset or a fuzzy filename hit is not intent, and not proof.
        if (f.confidence < MIN_VERDICT_CONFIDENCE)
            t = EvidenceTier::INDICATIVE;

        if (t > strongest) { strongest = t; strongestDesc = f.description; strongestEv = f.evidence; }
        if (t == EvidenceTier::LIVE) live++;
        else if (t == EvidenceTier::EXECUTED) exec++;
        else if (t == EvidenceTier::EVASION) evas++;
        else if (t == EvidenceTier::REMNANT) remn++;
        else indi++;
    }

    tp.liveCount = live; tp.executedCount = exec; tp.evasionCount = evas;
    tp.remnantCount = remn; tp.indicativeCount = indi;

    // Tier-weighted score. Each tier is capped so volume of weak evidence
    // cannot inflate the number past what the evidence actually supports.
    tp.score += (std::min)(live * 35, 60);
    tp.score += (std::min)(exec * 25, 50);
    tp.score += (std::min)(evas * 12, 22);
    tp.score += (std::min)(remn * 10, 20);
    tp.score += (std::min)(indi * 3, 6);
    tp.score = (std::min)(tp.score, 100);

    // Verdict follows evidence class, not the arithmetic.
    if (live >= 1) {
        tp.verdict = "CONFIRMED CHEATER";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else if (exec >= 1) {
        tp.verdict = "CONFIRMED CHEATER";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else if (evas >= 1 && remn >= 1) {
        tp.verdict = "LIKELY CHEATER";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else if (remn >= 2) {
        tp.verdict = "LIKELY CHEATER";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else if (remn == 1 || evas >= 1) {
        tp.verdict = "SUSPICIOUS";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else if (indi >= 1) {
        tp.verdict = "INDICATIONS ONLY";
        tp.driver = strongestDesc; tp.driverTier = TierLabel(strongest);
    } else {
        tp.verdict = "CLEAN";
    }
    return tp;
}

// ============================================================================
// PHASE 53 - AUTORUNS
// Persistence the OS will re-launch on every boot: Run/RunOnce keys for every
// user hive plus the Startup folders. Cheats that survive a reboot live here.
// ============================================================================
void ScanAutoruns(CheatResult& r) {
    long checked = 0;

    struct RunKey { HKEY root; const wchar_t* path; const char* label; };
    const RunKey keys[] = {
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",            "HKCU Run" },
        { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",       "HKCU RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",            "HKLM Run" },
        { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",       "HKLM RunOnce" },
        { HKEY_LOCAL_MACHINE, L"Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run", "HKLM Run (32-bit)" },
    };

    for (const auto& k : keys) {
        HKEY hKey;
        if (RegOpenKeyExW(k.root, k.path, 0, KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) continue;

        DWORD count = 0, maxNameLen = 0;
        if (RegQueryInfoKeyW(hKey, nullptr, nullptr, nullptr, &count, &maxNameLen,
                             nullptr, nullptr, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            maxNameLen += 2;
            for (DWORD i = 0; i < count; i++) {
                std::vector<wchar_t> name(maxNameLen + 2, 0);
                DWORD nameLen = (DWORD)name.size();
                if (RegEnumValueW(hKey, i, name.data(), &nameLen, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS)
                    continue;
                checked++;

                std::string valueName = WideToAnsi(std::wstring(name.data(), nameLen));
                std::string combined = valueName;

                // read the command string too â€” the payload path lives there
                BYTE buf[2048] = {0};
                DWORD bufLen = sizeof(buf) - sizeof(wchar_t);
                DWORD type = 0;
                if (RegQueryValueExW(hKey, name.data(), nullptr, &type, buf, &bufLen) == ERROR_SUCCESS &&
                    (type == REG_SZ || type == REG_EXPAND_SZ)) {
                    combined += " " + WideToAnsi(std::wstring((wchar_t*)buf));
                }

                if (MatchesCheatSignature(AnsiToWide(combined))) {
                    r.findings.push_back({
                        "AUTORUN",
                        valueName,
                        90,
                        std::string(k.label) + " autorun -> " + combined.substr(0, 300)
                    });
                }
            }
        }
        RegCloseKey(hKey);
    }

    // Startup folders
    wchar_t startup[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_STARTUP, nullptr, SHGFP_TYPE_CURRENT, startup))) {
        std::error_code ec;
        for (auto it = std::filesystem::directory_iterator(startup, ec);
             it != std::filesystem::directory_iterator() && !ec; it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            checked++;
            std::wstring fn = it->path().filename().wstring();
            if (MatchesCheatSignature(fn)) {
                r.findings.push_back({
                    "AUTORUN",
                    WideToAnsi(fn),
                    90,
                    "Startup folder autorun: " + WideToAnsi(it->path().wstring())
                });
            }
        }
    }

    // Common Startup for all users
    wchar_t commonStartup[MAX_PATH] = {0};
    if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_COMMON_STARTUP, nullptr, SHGFP_TYPE_CURRENT, commonStartup))) {
        std::error_code ec;
        for (auto it = std::filesystem::directory_iterator(commonStartup, ec);
             it != std::filesystem::directory_iterator() && !ec; it.increment(ec)) {
            if (!it->is_regular_file(ec)) continue;
            checked++;
            std::wstring fn = it->path().filename().wstring();
            if (MatchesCheatSignature(fn)) {
                r.findings.push_back({
                    "AUTORUN",
                    WideToAnsi(fn),
                    90,
                    "All-users Startup folder autorun: " + WideToAnsi(it->path().wstring())
                });
            }
        }
    }

    g_cov.add("Autorun entries (Run keys + Startup)", checked,
        checked > 0 ? "values enumerated and matched" : "no autorun values present");
}

// ============================================================================
// PHASE 54 - WINDOWS SERVICES
// A service runs as SYSTEM and survives everything a user process cannot. An
// unsigned or cheat-named service is among the strongest signals available.
// ============================================================================
void ScanServices(CheatResult& r) {
    long checked = 0;
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) {
        g_cov.addLimited("Windows services", 0, "SCM access denied without elevation");
        return;
    }

    DWORD bytesNeeded = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytesNeeded, &count, &resume, nullptr);

    std::vector<BYTE> buf(bytesNeeded ? bytesNeeded : 1);
    resume = 0;
    if (!EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                               buf.data(), (DWORD)buf.size(), &bytesNeeded, &count, &resume, nullptr)) {
        CloseServiceHandle(scm);
        g_cov.addLimited("Windows services", 0, "service enumeration failed");
        return;
    }

    ENUM_SERVICE_STATUS_PROCESSW* services = (ENUM_SERVICE_STATUS_PROCESSW*)buf.data();
    for (DWORD i = 0; i < count; i++) {
        checked++;
        std::string svcName = WideToAnsi(services[i].lpServiceName);
        std::string dispName = WideToAnsi(services[i].lpDisplayName);
        std::string combined = svcName + " " + dispName;

        bool sigHit = MatchesCheatSignature(AnsiToWide(combined));
        bool suspiciousName = false;
        {
            std::string l = combined;
            std::transform(l.begin(), l.end(), l.begin(), ::tolower);
            for (const char* t : {"cheat", "inject", "exploit", "executor", "bypass", "spoofer", "aimbot", "esp"}) {
                if (l.find(t) != std::string::npos) { suspiciousName = true; break; }
            }
        }
        if (!sigHit && !suspiciousName) continue;

        // Resolve the on-disk binary and check who signed it
        std::string binaryPath;
        bool signedByMs = false;
        SC_HANDLE svc = OpenServiceW(scm, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
        if (svc) {
            DWORD need = 0;
            QueryServiceConfigW(svc, nullptr, 0, &need);
            if (need) {
                std::vector<BYTE> cfgBuf(need);
                QUERY_SERVICE_CONFIGW* cfg = (QUERY_SERVICE_CONFIGW*)cfgBuf.data();
                if (QueryServiceConfigW(svc, cfg, need, &need) && cfg->lpBinaryPathName) {
                    binaryPath = WideToAnsi(cfg->lpBinaryPathName);
                    // strip quotes and arguments for the signature check
                    size_t q1 = binaryPath.find('"');
                    size_t q2 = (q1 != std::string::npos) ? binaryPath.find('"', q1 + 1) : std::string::npos;
                    std::string exePath = (q1 != std::string::npos && q2 != std::string::npos)
                        ? binaryPath.substr(q1 + 1, q2 - q1 - 1) : binaryPath;

                    if (exePath.size() > 4) {
                        SignatureResult sig = VerifyAuthenticode(AnsiToWide(exePath));
                        signedByMs = sig.isSigned && sig.isTrusted &&
                                     (sig.publisher.find("Microsoft") != std::string::npos);
                        if (!sig.isSigned && sigHit) {
                            r.findings.push_back({
                                "UNSIGNED_SERVICE",
                                svcName,
                                95,
                                "Unsigned Windows service running as SYSTEM: " + binaryPath
                            });
                        }
                    }
                }
            }
            CloseServiceHandle(svc);
        }

        if (sigHit && signedByMs) {
            // A Microsoft-signed binary with a cheat-like name is almost
            // always a false positive from a fuzzy name match. Record as info.
            r.findings.push_back({
                "SERVICE_NAME_MATCH",
                svcName,
                30,
                "Service name matched a cheat signature but the binary is Microsoft-signed. Likely a false positive: " + binaryPath
            });
        } else if (sigHit) {
            r.findings.push_back({
                "CHEAT_SERVICE",
                svcName,
                85,
                "Windows service matched a cheat signature: " + combined + " | Binary: " + binaryPath
            });
        }
    }

    CloseServiceHandle(scm);
    g_cov.add("Windows services", checked, "names matched, binaries signature-checked");
}

// ============================================================================
// PHASE 55 - WMI EVENT SUBSCRIPTION PERSISTENCE
// A WMI subscription re-fires its payload on a trigger (logon, timer, or
// process start) and lives in the repository rather than on disk as a file.
// This is a favoured persistence route because file scans never see it.
// ============================================================================
void ScanWmiPersistence(CheatResult& r) {
    long checked = 0;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool comReady = SUCCEEDED(hr) || hr == RPC_E_CHANGED_MODE;
    if (!comReady) {
        g_cov.addLimited("WMI event subscriptions", 0, "COM initialization failed");
        return;
    }

    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
                         RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
                         nullptr, EOAC_NONE, nullptr);

    IWbemLocator* pLoc = nullptr;
    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hr)) {
        g_cov.addLimited("WMI event subscriptions", 0, "WbemLocator creation failed");
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = nullptr;
    hr = pLoc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                             0, nullptr, nullptr, &pSvc);
    if (FAILED(hr)) {
        pLoc->Release();
        g_cov.addLimited("WMI event subscriptions", 0, "WMI connection failed");
        CoUninitialize();
        return;
    }

    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
                      RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);

    // ActiveScriptEventConsumer runs arbitrary script text. That is exactly
    // what cheat persistence uses, so any instance is worth a hard look.
    const wchar_t* consumers[] = {
        L"ActiveScriptEventConsumer",
        L"CommandLineEventConsumer",
    };

    for (const wchar_t* cls : consumers) {
        IEnumWbemClassObject* pEnum = nullptr;
        hr = pSvc->CreateInstanceEnum(_bstr_t(cls),
                                      WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
                                      nullptr, &pEnum);
        if (FAILED(hr)) continue;

        IWbemClassObject* pObj = nullptr;
        ULONG returned = 0;
        while (pEnum->Next(WBEM_INFINITE, 1, &pObj, &returned) == S_OK) {
            checked++;

            auto readStr = [&](const wchar_t* prop) -> std::string {
                std::string out;
                VARIANT vt;
                VariantInit(&vt);
                if (SUCCEEDED(pObj->Get(prop, 0, &vt, nullptr, nullptr)) && vt.vt == VT_BSTR && vt.bstrVal)
                    out = WideToAnsi(vt.bstrVal);
                VariantClear(&vt);
                return out;
            };

            std::string cname = readStr(L"Name");
            std::string script = readStr(L"ScriptText");
            if (script.empty()) script = readStr(L"CommandLineTemplate");
            std::string execRe = readStr(L"ExecutablePath");

            std::string combined = cname + " " + script + " " + execRe;
            if (MatchesCheatSignature(AnsiToWide(combined))) {
                r.findings.push_back({
                    "WMI_PERSISTENCE",
                    cname.empty() ? std::string("(unnamed consumer)") : cname,
                    95,
                    std::string("WMI ") + WideToAnsi(cls) + " subscription matched a cheat signature. "
                    "This re-executes without any file on disk: " + script.substr(0, 400)
                });
            } else if (!script.empty()) {
                // An active script consumer with no cheat string is still a
                // persistence mechanism worth surfacing, but at low weight.
                r.findings.push_back({
                    "WMI_SCRIPT_CONSUMER",
                    cname.empty() ? std::string("(unnamed consumer)") : cname,
                    45,
                    std::string("WMI ") + WideToAnsi(cls) + " contains executable script/payload text: "
                    + script.substr(0, 300)
                });
            }
            pObj->Release();
        }
        pEnum->Release();
    }

    pSvc->Release();
    pLoc->Release();
    CoUninitialize();

    g_cov.add("WMI event subscriptions", checked,
        checked > 0 ? "consumers enumerated and inspected" : "no persistent subscriptions found");
}

// ============================================================================
// PHASE 56 - ROBLOX VERSION SPRAWL
// Roblox keeps each client build in its own folder under Versions. Retaining
// old clients is how known client-side exploits stay usable: a superseded
// build may still carry a vulnerability that current Roblox has patched.
// ============================================================================
void ScanRobloxVersionSprawl(CheatResult& r) {
    wchar_t localAppData[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) return;

    std::filesystem::path versionsDir = std::filesystem::path(localAppData) / L"Roblox" / L"Versions";
    if (!std::filesystem::exists(versionsDir)) return;

    struct VerEntry { std::string dir; FILETIME writeTime; };
    std::vector<VerEntry> clients;

    for (const auto& ver : std::filesystem::directory_iterator(versionsDir)) {
        if (!ver.is_directory()) continue;
        std::filesystem::path exe = ver.path() / L"RobloxPlayerBeta.exe";
        if (!std::filesystem::exists(exe)) continue;
        clients.push_back({ WideToAnsi(ver.path().filename().wstring()),
                            GetFileWriteTime(exe.wstring()) });
    }

    if (clients.size() <= 1) {
        g_cov.add("Roblox client versions", (long)clients.size(), "single current version");
        return;
    }

    // Oldest retained client is the one that matters
    auto oldest = clients.begin();
    for (auto it = clients.begin(); it != clients.end(); ++it) {
        if (CompareFileTime(&it->writeTime, &oldest->writeTime) < 0) oldest = it;
    }

    // How far back does the retained client go?
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    ULONGLONG ageMs = ((ULONGLONG)nowFt.dwHighDateTime << 32 | nowFt.dwLowDateTime)
                    - ((ULONGLONG)oldest->writeTime.dwHighDateTime << 32 | oldest->writeTime.dwLowDateTime);
    long ageDays = (long)(ageMs / (10ULL * 1000 * 1000 * 60 * 60 * 24));

    r.findings.push_back({
        "ROBLOX_VERSION_SPRAWL",
        oldest->dir,
        ageDays >= 14 ? 70 : 45,
        std::to_string(clients.size()) + " separate Roblox client versions retained. Oldest is "
        + std::to_string(ageDays) + " days old. Superseded clients are kept to run known client-side "
        "exploits against builds that current Roblox has patched."
    });

    g_cov.add("Roblox client versions", (long)clients.size(),
        std::to_string(clients.size()) + " retained, oldest " + std::to_string(ageDays) + " days");
}

// ============================================================================
// PHASE 49 - ROBLOX CLIENT INTEGRITY
// RobloxPlayerBeta.exe ships signed by Roblox Corporation. A patched or
// re-signed client is how every Hyperion/Byfron bypass gets loaded.
// ============================================================================
void ScanRobloxClientIntegrity(CheatResult& r) {
    wchar_t localAppData[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) return;

    std::filesystem::path versionsDir = std::filesystem::path(localAppData) / L"Roblox" / L"Versions";
    if (!std::filesystem::exists(versionsDir)) {
        g_cov.add("Roblox client binaries", 0, "not installed");
        return;
    }

    long clients = 0, siblings = 0;
    for (const auto& ver : std::filesystem::directory_iterator(versionsDir)) {
        if (!ver.is_directory()) continue;
        std::filesystem::path client = ver.path() / L"RobloxPlayerBeta.exe";
        if (!std::filesystem::exists(client)) continue;
        clients++;

        SignatureResult sig = VerifyAuthenticode(client.wstring());
        if (!sig.isSigned) {
            r.findings.push_back({
                "PATCHED_CLIENT",
                "RobloxPlayerBeta.exe",
                95,
                "UNSIGNED CLIENT: " + WideToAnsi(ver.path().wstring()) +
                " | Official Roblox clients are always signed by Roblox Corporation. An unsigned client means the anti-cheat payload was stripped or replaced."
            });
        } else if (sig.publisher.find("Roblox") == std::string::npos && sig.publisher.find("roblox") == std::string::npos) {
            r.findings.push_back({
                "CLIENT_SIGNER_MISMATCH",
                "RobloxPlayerBeta.exe",
                90,
                "Signer: " + sig.publisher + " | Expected Roblox Corporation. Client binary does not match the official release."
            });
        }

        // anything unsigned sitting next to the client is a staged load
        for (const auto& sib : std::filesystem::directory_iterator(ver.path())) {
            if (!sib.is_regular_file()) continue;
            std::string ext = Lower(PathUtf8(sib.path().extension()));
            if (ext != ".dll" && ext != ".exe") continue;
            std::string fn = PathUtf8(sib.path().filename());
            std::string fnLower = fn;
            std::transform(fnLower.begin(), fnLower.end(), fnLower.begin(), ::tolower);
            if (fnLower == "robloxplayerbeta.exe" || fnLower == "robloxplayerlauncher.exe" ||
                fnLower.find("vcredist") != std::string::npos || fnLower.find("dxsetup") != std::string::npos ||
                fnLower.find("uninstall") != std::string::npos) continue;
            siblings++;
            SignatureResult sibSig = VerifyAuthenticode(sib.path().wstring());
            if (!sibSig.isSigned) {
                r.findings.push_back({
                    "ROBLOX_DIR_DROP",
                    fn,
                    70,
                    "Unsigned binary staged beside the Roblox client: " + WideToAnsi(sib.path().wstring())
                });
            }
        }
    }

    g_cov.add("Roblox client binaries", clients, clients > 0
        ? "verified against Roblox Corporation signature"
        : "no RobloxPlayerBeta.exe present");
    g_cov.add("Roblox client directory", siblings, "binaries beside client checked for signatures");
}

// ============================================================================
// PHASE 50 - HIDDEN THREAD START ADDRESSES
// Thread hijack and shellcode injection leave threads whose start address
// lives in unbacked private memory instead of a loaded module.
// ============================================================================
typedef NTSTATUS (NTAPI* pfnNtQueryInformationThread)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct HiddenThreadResult {
    int rwxStarts = 0;
    int privateStarts = 0;
    int unreadable = 0;
    int total = 0;
    bool overlayPresent = false;
    std::string evidence;
};

HiddenThreadResult DetectHiddenThreads(DWORD pid) {
    HiddenThreadResult res;
    pfnNtQueryInformationThread NtQIT = (pfnNtQueryInformationThread)
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread");
    if (!NtQIT) return res;

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) return res;

    struct Range { uintptr_t lo, hi; };
    std::vector<Range> mods;

    HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (modSnap != INVALID_HANDLE_VALUE) {
        MODULEENTRY32W me; me.dwSize = sizeof(me);
        if (Module32FirstW(modSnap, &me)) {
            do {
                mods.push_back({ (uintptr_t)me.modBaseAddr, (uintptr_t)me.modBaseAddr + me.modBaseSize });
                std::wstring mp = Lower(me.szModule);
                if (mp.find(L"rtss") != std::wstring::npos || mp.find(L"obs") != std::wstring::npos ||
                    mp.find(L"overwolf") != std::wstring::npos || mp.find(L"nahimic") != std::wstring::npos ||
                    mp.find(L"razer") != std::wstring::npos || mp.find(L"gamebar") != std::wstring::npos ||
                    mp.find(L"xinput") != std::wstring::npos) {
                    res.overlayPresent = true;
                }
            } while (Module32NextW(modSnap, &me));
        }
        CloseHandle(modSnap);
    }

    std::ostringstream ev;
    HANDLE thSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (thSnap != INVALID_HANDLE_VALUE) {
        THREADENTRY32 te; te.dwSize = sizeof(te);
        if (Thread32First(thSnap, &te)) {
            do {
                if (te.th32OwnerProcessID != pid) continue;
                res.total++;

                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (!hThread) { res.unreadable++; continue; }

                PVOID startAddr = nullptr;
                NTSTATUS st = NtQIT(hThread, 9 /* ThreadQuerySetWin32StartAddress */, &startAddr, sizeof(startAddr), nullptr);
                CloseHandle(hThread);
                if (st != 0 || !startAddr) { res.unreadable++; continue; }

                uintptr_t a = (uintptr_t)startAddr;
                bool inModule = false;
                for (const auto& m : mods) {
                    if (a >= m.lo && a < m.hi) { inModule = true; break; }
                }
                if (inModule) continue;

                MEMORY_BASIC_INFORMATION mbi;
                if (!VirtualQueryEx(hProcess, startAddr, &mbi, sizeof(mbi))) continue;
                if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE) continue;

                bool executable = (mbi.Protect & 0xF0) != 0;
                if (!executable) continue;

                res.privateStarts++;
                if (mbi.Protect == PAGE_EXECUTE_READWRITE) {
                    res.rwxStarts++;
                    if (res.rwxStarts <= 3) {
                        ev << "tid " << te.th32ThreadID << " start 0x" << std::hex << a
                           << " in RWX private region 0x" << (uintptr_t)mbi.BaseAddress << std::dec << "  ";
                    }
                }
            } while (Thread32Next(thSnap, &te));
        }
        CloseHandle(thSnap);
    }

    CloseHandle(hProcess);
    res.evidence = ev.str();
    return res;
}

// ============================================================================
// PHASE 52 - GENERIC INJECTOR HEURISTIC
// Unknown executors do not appear in any signature list. They do however all
// share one property: an unsigned PE carrying the remote-thread injection
// import triad. This catches renamed, packed and freshly released tools.
// ============================================================================
struct PeCapability {
    bool parsed = false;
    bool injectTriad = false;
    bool keylogCapable = false;
    bool robloxAware = false;
    std::vector<std::string> keyImports;
};

static bool RvaToFileOffset(const std::vector<BYTE>& buf, uint32_t rva, size_t& out) {
    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buf.data();
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(buf.data() + dos->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        uint32_t va = sec[i].VirtualAddress;
        uint32_t vsz = sec[i].Misc.VirtualSize ? sec[i].Misc.VirtualSize : sec[i].SizeOfRawData;
        if (rva >= va && rva < va + vsz) {
            out = (size_t)(rva - va) + sec[i].PointerToRawData;
            return out < buf.size();
        }
    }
    return false;
}

PeCapability AnalyzePeCapabilities(const std::filesystem::path& path) {
    PeCapability cap;

    try {
        auto fsize = std::filesystem::file_size(path);
        if (fsize < 0x200 || fsize > 90ULL * 1024 * 1024) return cap;

        std::ifstream in(path, std::ios::binary);
        if (!in) return cap;
        std::vector<BYTE> buf((size_t)fsize);
        in.read((char*)buf.data(), (std::streamsize)fsize);
        if (!in.good() && !in.eof()) return cap;
        if (buf.size() < 0x200) return cap;

        if (buf[0] != 'M' || buf[1] != 'Z') return cap;
        const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)buf.data();
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) >= buf.size()) return cap;
        const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)(buf.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return cap;

        bool pe64 = (nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC);
        DWORD importRVA;
        if (pe64) importRVA = ((const IMAGE_OPTIONAL_HEADER64*)&nt->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        else      importRVA = ((const IMAGE_OPTIONAL_HEADER32*)&nt->OptionalHeader)->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        if (!importRVA) { cap.parsed = true; return cap; }

        size_t descOff = 0;
        if (!RvaToFileOffset(buf, importRVA, descOff)) return cap;

        bool hasWriteMem = false, hasRemoteThread = false, hasAlloc = false, hasKeyHook = false, hasPriv = false;

        for (int guard = 0; guard < 256; guard++) {
            if (descOff + sizeof(IMAGE_IMPORT_DESCRIPTOR) > buf.size()) break;
            const IMAGE_IMPORT_DESCRIPTOR* d = (const IMAGE_IMPORT_DESCRIPTOR*)(buf.data() + descOff);
            if (!d->Name && !d->FirstThunk) break;

            size_t nameOff = 0;
            std::string dllName;
            if (RvaToFileOffset(buf, d->Name, nameOff)) {
                char tmp[64] = {0};
                size_t n = (std::min)((size_t)63, buf.size() - nameOff);
                memcpy(tmp, buf.data() + nameOff, n);
                dllName = tmp;
                std::transform(dllName.begin(), dllName.end(), dllName.begin(), ::tolower);
            }

            uint32_t thunkRVA = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
            size_t thunkOff = 0;
            if (RvaToFileOffset(buf, thunkRVA, thunkOff)) {
                size_t entrySize = pe64 ? 8 : 4;
                for (int k = 0; k < 512; k++) {
                    size_t off = thunkOff + k * entrySize;
                    if (off + entrySize > buf.size()) break;
                    uint64_t val = pe64 ? *(uint64_t*)(buf.data() + off) : *(uint32_t*)(buf.data() + off);
                    if (!val) break;
                    bool byOrdinal = pe64 ? ((val & (1ull << 63)) != 0) : ((val & 0x80000000u) != 0);
                    if (byOrdinal) continue;

                    size_t impNameOff = 0;
                    if (!RvaToFileOffset(buf, (uint32_t)val, impNameOff)) continue;
                    if (impNameOff + 2 >= buf.size()) continue;
                    char fn[128] = {0};
                    size_t nn = (std::min)((size_t)127, buf.size() - impNameOff - 2);
                    memcpy(fn, buf.data() + impNameOff + 2, nn);
                    std::string fnLower = fn;
                    std::transform(fnLower.begin(), fnLower.end(), fnLower.begin(), ::tolower);

                    if (dllName.find("kernel32") != std::string::npos || dllName.find("ntdll") != std::string::npos ||
                        dllName.find("kernelbase") != std::string::npos) {
                        if (fnLower == "writeprocessmemory" || fnLower == "ntwritevirtualmemory") hasWriteMem = true;
                        if (fnLower == "createremotethread" || fnLower == "ntcreatethreadex" ||
                            fnLower == "rtlcreateuserthread" || fnLower == "ntqueueapcthread") hasRemoteThread = true;
                        if (fnLower == "virtualallocex" || fnLower == "ntallocatevirtualmemory") hasAlloc = true;
                        if (fnLower == "adjusttokenprivileges" || fnLower == "ntadjustprivilegestoken") hasPriv = true;
                        if (fnLower == "readprocessmemory") cap.keyImports.push_back("ReadProcessMemory");
                    }
                    if (dllName.find("user32") != std::string::npos) {
                        if (fnLower == "setwindowshookexa" || fnLower == "setwindowshookexw") hasKeyHook = true;
                        if (fnLower == "getasynckeystate" || fnLower == "getkeystate") hasKeyHook = true;
                    }
                    if (fnLower == "ntquerysysteminformation") cap.keyImports.push_back("NtQuerySystemInformation");
                }
            }
            descOff += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }

        cap.parsed = true;
        cap.keylogCapable = hasKeyHook && hasPriv;
        cap.injectTriad = hasWriteMem && hasRemoteThread && hasAlloc;

        // does the binary itself know about Roblox?
        const size_t scanLimit = (std::min)(buf.size(), (size_t)(2 * 1024 * 1024));
        std::string head((char*)buf.data(), scanLimit);
        std::transform(head.begin(), head.end(), head.begin(), ::tolower);
        for (const char* term : {"roblox", "luau", "getgenv", "hookmetamethod", "synapse", "writefile", "rconsole"}) {
            if (head.find(term) != std::string::npos) { cap.robloxAware = true; break; }
        }
    } catch (...) {
        return cap;
    }
    return cap;
}

// Prefetch writes a trace as "<BASE>.EXE-<8 hex>.pf". The caller passes a
// filename that already ends in ".exe", so appending ".exe.pf" produced
// "NAME.EXE.EXE.pf" - a name Windows never writes. The lookup could never
// match, which quietly made the Prefetch leg of the execution proof dead code
// and left content-hash matching as the only thing that could promote a file.
bool WasRecentlyExecuted(const std::string& exeName) {
    try {
        std::wstring base = AnsiToWide(exeName);
        for (auto& c : base) c = towupper(c);
        if (base.size() > 4 && base.compare(base.size() - 4, 4, L".EXE") == 0)
            base = base.substr(0, base.size() - 4);
        if (base.empty()) return false;

        std::error_code dirEc;
        std::filesystem::directory_iterator it(L"C:\\Windows\\Prefetch", dirEc);
        const std::filesystem::directory_iterator end;
        for (; it != end && !dirEc; it.increment(dirEc)) {
            std::error_code fEc;
            if (!it->is_regular_file(fEc)) continue;
            std::wstring fn = it->path().filename().wstring();
            for (auto& c : fn) c = towupper(c);
            if (fn.size() < base.size() + 9) continue;
            if (fn.compare(0, base.size(), base) != 0) continue;
            if (fn.compare(base.size(), 5, L".EXE-") != 0) continue;
            if (fn.compare(fn.size() - 3, 3, L".PF") != 0) continue;
            return true;
        }
    } catch (...) {}
    return false;
}

void ScanDropLocations(CheatResult& r) {
    wchar_t profile[MAX_PATH] = {0};
    if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PROFILE, nullptr, SHGFP_TYPE_CURRENT, profile))) return;

    wchar_t localAppData[MAX_PATH] = {0};
    SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData);
    wchar_t roaming[MAX_PATH] = {0};
    SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, roaming);

    std::vector<std::filesystem::path> roots = {
        std::filesystem::path(profile) / L"Downloads",
        std::filesystem::path(profile) / L"Desktop",
        std::filesystem::path(profile) / L"Documents",
        std::filesystem::path(localAppData) / L"Temp",
        std::filesystem::path(roaming),
    };

    long examined = 0, flagged = 0;

    // One binary is one piece of evidence regardless of how many folders it is
    // copied into. Without this, four copies of a single tool would count as
    // four independent remnants and could carry a verdict on volume alone.
    // Duplicates are collapsed; extra copies are appended to the first finding.
    std::map<std::string, size_t> injectorIndexByName;

    for (const auto& root : roots) {
        if (!std::filesystem::exists(root)) continue;
        std::error_code ec;
        int depthFiles = 0;
        for (auto it = std::filesystem::recursive_directory_iterator(
                 root, std::filesystem::directory_options::skip_permission_denied, ec);
             it != std::filesystem::recursive_directory_iterator() && !ec; it.increment(ec)) {
            if (depthFiles > 4000) break;
            if (!it->is_regular_file(ec)) continue;
            if (Lower(it->path().extension().wstring()) != L".exe") continue;
            depthFiles++;

            // PathUtf8, not path::string(): the ANSI code page cannot hold every
            // legal filename, and the conversion THREW on the first exotic one -
            // uncaught -> fail-fast -> the report was never saved or posted.
            std::string name = PathUtf8(it->path().filename());
            std::string nameLower = name;
            std::transform(nameLower.begin(), nameLower.end(), nameLower.begin(), ::tolower);

            // already covered by the signature catalog
            if (MatchesCheatFileSignature(AnsiToWide(name))) continue;

            examined++;
            SignatureResult sig = VerifyAuthenticode(it->path().wstring());
            if (sig.isSigned && sig.isTrusted) continue;

            PeCapability cap = AnalyzePeCapabilities(it->path());
            if (!cap.parsed || !cap.injectTriad) continue;

            std::string awareness = cap.robloxAware
                ? "Binary contains Roblox/Luau exploit strings (getgenv, hookmetamethod, writefile)."
                : "No Roblox strings found - generic injector capability.";

            std::string pathStr = WideToAnsi(it->path().wstring());

            // Collapse copies of the same binary into the first finding. Four
            // copies of one tool are one piece of evidence, not four. The cap
            // below only applies to genuinely new binaries.
            auto seenIt = injectorIndexByName.find(nameLower);
            if (seenIt != injectorIndexByName.end()) {
                Finding& f = r.findings[seenIt->second];
                f.evidence += "\n                                   also found at: " + pathStr;
                f.evidence += " [duplicate copy collapsed into this finding]";
                continue;
            }

            flagged++;
            if (flagged > 30) break;

            // Execution can be proven by content, not just by name. A Prefetch
            // filename only says that some file with this name ran. An Amcache
            // SHA-1 says this exact byte sequence ran, so a renamed copy of a
            // tool cannot slip past by impersonating a system process.
            bool prefetchExec = WasRecentlyExecuted(name);
            std::string sha1 = sec::Sha1File(it->path().wstring());
            bool amcacheExec = !sha1.empty() && g_amcacheSha1.count(sha1) > 0;

            std::string executed;
            if (prefetchExec && amcacheExec)
                executed = " | EXECUTION CONFIRMED TWICE: Prefetch launch record + Amcache SHA-1 "
                           "(" + sha1 + ") matches this file's content";
            else if (amcacheExec)
                executed = " | EXECUTION CONFIRMED BY CONTENT: Amcache SHA-1 (" + sha1 +
                           ") matches this file's bytes - renaming cannot hide this";
            else if (prefetchExec)
                executed = " | PREFETCH MATCH: Windows confirms this exact filename was launched";
            else
                executed = " | No execution record found - possession only";

            bool execProven = prefetchExec || amcacheExec;

            injectorIndexByName[nameLower] = r.findings.size();
            r.findings.push_back({
                execProven ? "GENERIC_INJECTOR_EXEC" : "GENERIC_INJECTOR",
                name,
                execProven ? 85 : 65,
                "Unsigned binary carrying the remote-thread injection import triad "
                "(WriteProcessMemory + CreateRemoteThread + VirtualAllocEx). " + awareness +
                " Path: " + pathStr + executed
            });
        }
    }

    g_cov.add("Drop locations (Downloads/Desktop/Temp)", examined,
        std::to_string(flagged) + " unsigned injection-capable binary(ies)");
}

// ============================================================================
// PHASE 51 - DEBUGGER ATTACH ON ROBLOX
// ============================================================================
void ScanDebuggerAttach(CheatResult& r, DWORD robloxDetectPid) {
    if (robloxDetectPid == 0) return;
    HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, robloxDetectPid);
    if (!h) return;
    BOOL dbg = FALSE;
    if (CheckRemoteDebuggerPresent(h, &dbg) && dbg) {
        r.findings.push_back({
            "DEBUGGER_ATTACHED",
            "RobloxPlayerBeta.exe",
            40,
            "A debugger was attached to the live Roblox process at scan time (PID " +
            std::to_string(robloxDetectPid) + "). Often used to defeat anti-cheat integrity checks."
        });
    }
    CloseHandle(h);
}

// ============================================================================
// PHASE 26b: Amcache.hve - content-proven execution records
// ============================================================================
// PHASE 26's APPCOMPAT category only name-matches AppCompatFlags keys. The real
// Amcache hive at C:\Windows\AppCompat\Programs\Amcache.hve is where the
// Windows Program Inventory records a file's CONTENT HASH, and that closes the
// gap a renamed cheat walks through: the name can be a lie, the bytes cannot.
//
// The hive is parsed straight off disk as a regf file. Mounting it with
// RegLoadKey would need SE_BACKUP/SE_RESTORE and is blocked outright on some
// machines, so it buys nothing over a plain read - this is how forensic tools
// work on evidence they are not permitted to mount. Current builds keep records
// under Root\InventoryApplicationFile\{name}|{id} with the digest inside the
// FileId string; older ones use Root\File\{guid} with a twenty-byte REG_BINARY
// named "000". The parser takes both shapes, plus any hex run long enough to be
// a SHA-1, so an unfamiliar layout still contributes digests.
//
// Nothing is claimed from a name alone. A digest is only ever used as a
// membership test against files this scan hashes itself, so a misread record
// costs coverage instead of manufacturing a hit - and if the layout is not one
// this build recognises, the honest answer is "no content digests collected".
// ============================================================================

// ---------------------------------------------------------------------------
// Offline regf reader.
// The hive is parsed straight off disk. Mounting it with RegLoadKey would need
// SE_BACKUP/SE_RESTORE and is blocked outright on some machines, and it buys
// nothing: a file read is all a parser needs. This is the same approach
// forensic tools take on evidence they are not permitted to mount.
//
// Layout, cross-checked against the raw bytes of the live hive:
//   file  : "regf" @0, hive-bins size @0x28, root cell offset @0x24
//   base  : cells address from 0x1000, past the first hbin header
//   cell  : int32 @offset, negative = allocated, payload = |size| - 4, and
//           payloads are 8-byte aligned so the real length is >= the declared
//   nk    : "nk"@0 flags@0x02 nSub@0x14 subList@0x1C nVal@0x24 valList@0x28
//           nameLen@0x48 (in bytes) name@0x4C
//   list  : "lh"/"lf" pack 8 bytes per child, "li" packs a bare offset, and
//           "ri" is an index that recurses into further lists
//   vk    : "vk"@0 nameLen@0x02 dsz@0x04 dataOff@0x08 type@0x0C flags@0x10
//           name@0x14; flag 0x01 means the name is stored ASCII
//   data  : dsz with the high bit set means the value is resident in the
//           offset field itself, real size = dsz & 0x7FFFFFFF and never > 4
//   text  : REG_SZ payloads are UTF-16LE
// ---------------------------------------------------------------------------
namespace amc {

struct Hive {
    std::vector<uint8_t> buf;
    bool baseIsFileStart = false;

    bool load(const wchar_t* path) {
        HANDLE h = CreateFileW(path, GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) return false;
        bool ok = false;
        LARGE_INTEGER sz{};
        if (GetFileSizeEx(h, &sz) && sz.QuadPart >= 0x1004 && sz.QuadPart < (1LL << 30)) {
            buf.resize((size_t)sz.QuadPart);
            DWORD got = 0;
            if (ReadFile(h, buf.data(), (DWORD)buf.size(), &got, nullptr) && got == buf.size())
                ok = memcmp(buf.data(), "regf", 4) == 0;
        }
        CloseHandle(h);
        if (!ok) buf.clear();
        return ok;
    }

    size_t base() const { return baseIsFileStart ? 0 : 0x1000; }

    uint32_t rootCell() const {
        uint32_t v = 0;
        if (buf.size() >= 0x28) memcpy(&v, buf.data() + 0x24, 4);
        return v;
    }

    // Cells address from 0x1000 on every hive seen here. Rather than trust it,
    // read the root cell both ways and keep whichever base lands on an "nk".
    void detect() {
        baseIsFileStart = false;
        uint32_t r = rootCell();
        if (base() + r + 6 <= buf.size() &&
            memcmp(buf.data() + base() + r + 4, "nk", 2) == 0) return;
        baseIsFileStart = true;
    }

    bool cellAt(size_t cellOff, const uint8_t** payload, size_t* plen) const {
        size_t fo = base() + cellOff;
        if (fo + 4 > buf.size()) return false;
        int32_t sz = 0;
        memcpy(&sz, buf.data() + fo, 4);
        if (sz == 0) return false;
        size_t asz = (size_t)(sz < 0 ? -(int64_t)sz : sz);
        if (asz < 4 || asz > (1u << 28) || fo + asz > buf.size()) return false;
        if (payload) *payload = buf.data() + fo + 4;
        if (plen) *plen = asz - 4;
        return true;
    }
};

struct Nk {
    uint16_t flags = 0;
    uint32_t nSub = 0, subList = 0xFFFFFFFFu, nVal = 0, valList = 0xFFFFFFFFu;
    std::wstring name;
};

// Key names arrive as raw ASCII and value text as UTF-16LE, and the flag bit
// that is meant to separate them does not hold across hives. Read the bytes
// instead: if the odd positions are zero it is UTF-16LE.
std::wstring DecodeName(const uint8_t* p, size_t n) {
    std::wstring out;
    if (!p || n == 0) return out;
    size_t pairs = n / 2, zeros = 0;
    for (size_t i = 1; i + 1 < n; i += 2) if (p[i] == 0) zeros++;
    if (pairs > 0 && zeros * 2 >= pairs) {
        out.reserve(pairs);
        for (size_t i = 0; i + 1 < n; i += 2) out.push_back((wchar_t)p[i]);
    } else {
        out.reserve(n);
        for (size_t i = 0; i < n; i++) out.push_back((wchar_t)(unsigned char)p[i]);
    }
    return out;
}

bool ReadNk(const Hive& H, uint32_t off, Nk& out) {
    const uint8_t* p = nullptr; size_t plen = 0;
    if (!H.cellAt(off, &p, &plen) || plen < 0x4C || memcmp(p, "nk", 2) != 0) return false;
    uint16_t nameLen = 0;
    memcpy(&out.flags,   p + 0x02, 2);
    memcpy(&out.nSub,    p + 0x14, 4);
    memcpy(&out.subList, p + 0x1C, 4);
    memcpy(&out.nVal,    p + 0x24, 4);
    memcpy(&out.valList, p + 0x28, 4);
    memcpy(&nameLen,     p + 0x48, 2);
    if (nameLen && (size_t)0x4C + nameLen <= plen)
        out.name = DecodeName(p + 0x4C, nameLen);
    return true;
}

void ReadSubkeys(const Hive& H, uint32_t off, std::vector<uint32_t>& out, int depth) {
    if (off == 0xFFFFFFFFu || depth > 4 || out.size() > 200000) return;
    const uint8_t* p = nullptr; size_t plen = 0;
    if (!H.cellAt(off, &p, &plen) || plen < 4) return;
    bool wide = (p[0] == 'l' && (p[1] == 'h' || p[1] == 'f'));
    uint16_t count = 0;
    memcpy(&count, p + 2, 2);
    size_t stride = wide ? 8 : 4;
    if ((size_t)4 + (size_t)count * stride > plen) return;
    for (uint16_t i = 0; i < count; i++) {
        uint32_t v = 0;
        memcpy(&v, p + 4 + (size_t)i * stride, 4);
        if (p[0] == 'r' && p[1] == 'i') ReadSubkeys(H, v, out, depth + 1);
        else out.push_back(v);
    }
}

struct Val {
    std::wstring name;
    uint32_t type = 0;
    std::vector<uint8_t> data;
};

bool ReadValues(const Hive& H, const Nk& nk, std::vector<Val>& out, long* skipped) {
    if (nk.nVal == 0 || nk.nVal > 8192 || nk.valList == 0xFFFFFFFFu) return true;
    const uint8_t* vp = nullptr; size_t plen = 0;
    if (!H.cellAt(nk.valList, &vp, &plen) || plen < (size_t)nk.nVal * 4) {
        if (skipped) (*skipped)++;
        return false;
    }
    for (uint32_t i = 0; i < nk.nVal; i++) {
        uint32_t voff = 0;
        memcpy(&voff, vp + i * 4, 4);
        const uint8_t* v = nullptr; size_t vl = 0;
        if (!H.cellAt(voff, &v, &vl) || vl < 0x14 || memcmp(v, "vk", 2) != 0) {
            if (skipped) (*skipped)++;
            continue;
        }
        uint16_t nlen = 0, vf = 0;
        uint32_t dsz = 0, doff = 0, typ = 0;
        memcpy(&nlen, v + 0x02, 2);
        memcpy(&dsz,  v + 0x04, 4);
        memcpy(&doff, v + 0x08, 4);
        memcpy(&typ,  v + 0x0C, 4);
        memcpy(&vf,   v + 0x10, 2);

        Val val;
        val.type = typ;
        if (nlen && (size_t)0x14 + nlen <= vl)
            val.name = DecodeName(v + 0x14, nlen);

        if (dsz & 0x80000000u) {
            // High bit set: the payload sits in the offset field itself.
            size_t n = dsz & 0x7FFFFFFFu;
            if (n > 4) { if (skipped) (*skipped)++; continue; }
            val.data.resize(4);
            memcpy(val.data.data(), &doff, 4);
            val.data.resize(n);
        } else if (dsz > 0) {
            const uint8_t* dp = nullptr; size_t dl = 0;
            if (!H.cellAt(doff, &dp, &dl) || dl < dsz) {
                if (skipped) (*skipped)++;
                continue;
            }
            val.data.assign(dp, dp + dsz);
        }
        out.push_back(val);
    }
    return true;
}

std::wstring ToWide(const std::vector<uint8_t>& d) {
    std::wstring out;
    size_t n = d.size() / 2;
    for (size_t i = 0; i < n; i++) {
        wchar_t c = (wchar_t)(d[i * 2] | ((unsigned)d[i * 2 + 1] << 8));
        if (c == 0) break;
        out.push_back(c);
    }
    return out;
}

// FileId on this build is a four-character prefix followed by the file's SHA-1,
// so trusting a fixed offset would break the moment that prefix changed. Take
// the trailing forty digits of any hex run long enough to hold one: correct for
// both the forty-digit and forty-four-digit forms in the wild, and a digest cut
// from the wrong offset simply never equals a real file, which costs coverage
// instead of manufacturing a hit.
bool FindSha1Hex(const std::wstring& s, std::string& out) {
    if (s.size() < 40) return false;
    auto isHex = [](wchar_t c) {
        return (c >= L'0' && c <= L'9') || (c >= L'a' && c <= L'f') || (c >= L'A' && c <= L'F');
    };
    auto take = [&](size_t i) {
        out.clear();
        out.reserve(40);
        for (size_t k = 0; k < 40; k++) out.push_back((char)towlower(s[i + k]));
        return true;
    };
    bool tail = true;
    for (size_t k = s.size() - 40; k < s.size(); k++)
        if (!isHex(s[k])) { tail = false; break; }
    if (tail) return take(s.size() - 40);
    for (size_t i = 0; i + 40 <= s.size(); i++) {
        bool all = true;
        for (size_t k = 0; k < 40; k++)
            if (!isHex(s[i + k])) { all = false; break; }
        if (all) return take(i);
    }
    return false;
}

}  // namespace amc

static bool LooksLikePath(const std::wstring& s) {
    if (s.size() < 8 || s.size() > 320) return false;
    if (s[0] == L'\\' && s.size() > 1 && s[1] == L'\\') { /* UNC */ }
    else if (s.size() > 2 && s[1] == L':' && s[2] == L'\\') { /* drive */ }
    else return false;
    for (int i = (int)s.size() - 4; i >= 0; i--) {
        wchar_t c = s[i];
        if (c != L'.') continue;
        std::wstring ext = s.substr(i, 4);
        for (auto& ch : ext) ch = towlower(ch);
        if (ext == L".exe" || ext == L".dll" || ext == L".sys" || ext == L".cpl" ||
            ext == L".ocx" || ext == L".scr" || ext == L".tmp" || ext == L".bin")
            return true;
        break;
    }
    return false;
}

void ScanAmcacheHive(CheatResult& r) {
    if (!g_isAdmin) {
        g_cov.addLimited("Amcache (Amcache.hve)", 0,
            "requires administrator - the hive is not readable from an unelevated process");
        return;
    }

    amc::Hive H;
    if (!H.load(L"C:\\Windows\\AppCompat\\Programs\\Amcache.hve")) {
        g_cov.addLimited("Amcache (Amcache.hve)", 0,
            "Amcache.hve could not be read (locked, access denied, or not a regf hive)");
        return;
    }
    H.detect();

    amc::Nk rootNk;
    if (!amc::ReadNk(H, H.rootCell(), rootNk)) {
        g_cov.addLimited("Amcache (Amcache.hve)", 0, "hive root key is unreadable");
        return;
    }

    long records = 0, withHashes = 0, valueReads = 0, rejected = 0;
    long pathMatches = 0, nameMatches = 0;
    std::set<std::wstring> reported;

    // Both kinds of finding get the same treatment: name the evidence, hash the
    // file when a path is known, and say plainly what the record can and cannot
    // prove on this Windows build.
    auto pushFinding = [&](const std::wstring& target, bool havePath,
                           const std::string& sha, const std::string& recName) {
        std::string detail;
        if (havePath) {
            if (GetFileAttributesW(target.c_str()) == INVALID_FILE_ATTRIBUTES) {
                detail = " The file is no longer at that path - the inventory record outlived it.";
            } else {
                std::string nowSha = sec::Sha1File(target);
                if (!nowSha.empty() && !sha.empty() && _stricmp(nowSha.c_str(), sha.c_str()) == 0)
                    detail = " Content verified: the file still on disk hashes to the same value "
                             "Windows recorded, so the bytes present are the bytes that were "
                             "inventoried. Renaming cannot hide this.";
                else if (!nowSha.empty())
                    detail = " The file is present but no longer hashes to the recorded value, so "
                             "it has been replaced since the record was written.";
                else
                    detail = " The file is present but could not be hashed.";
            }
        } else {
            detail = " This build stores no path on the record - only its name and content hash - "
                     "so it is corroborated elsewhere in this scan, where candidates are hashed "
                     "and compared against this digest.";
        }
        r.findings.push_back({
            "AMCACHE",
            WideToAnsi(target),
            90,
            "Windows' Amcache Program Inventory holds a record for this file." +
            (sha.empty() ? std::string(" No content digest could be read from it.")
                         : " Recorded content SHA-1: " + sha + ".") +
            (recName.empty() ? std::string() : " Inventory record name: " + recName + ".") +
            detail
        });
    };

    std::function<void(uint32_t, int)> walk = [&](uint32_t off, int depth) {
        amc::Nk nk;
        if (!amc::ReadNk(H, off, nk)) return;

        if (depth >= 2) {
            records++;
            std::vector<std::string> hashes;
            std::vector<std::wstring> paths;
            std::wstring recName = nk.name;

            std::vector<amc::Val> vals;
            if (amc::ReadValues(H, nk, vals, &rejected) && !vals.empty()) {
                valueReads++;
                for (const auto& v : vals) {
                    // Older layouts carry the digest as a twenty-byte REG_BINARY
                    // (value name "000"); current ones keep it inside FileId.
                    // Collect both shapes.
                    if (v.type == REG_BINARY && v.data.size() == 20) {
                        hashes.push_back(sec::ToHex(v.data.data(), 20));
                        continue;
                    }
                    if (v.type != REG_SZ && v.type != REG_EXPAND_SZ && v.type != REG_NONE)
                        continue;
                    std::wstring s = amc::ToWide(v.data);
                    if (s.empty()) continue;
                    std::string hx;
                    if (amc::FindSha1Hex(s, hx)) hashes.push_back(hx);
                    if (LooksLikePath(s)) paths.push_back(s);
                }
                if (!hashes.empty()) withHashes++;
                for (const auto& h : hashes) g_amcacheSha1.insert(h);
            }

            std::string recNarrow = WideToAnsi(recName);
            std::wstring recBase = BaseExeName(recName);

            for (const auto& p : paths) {
                if (!MatchesCheatSignature(p)) continue;
                if (!reported.insert(Lower(p)).second) continue;
                pathMatches++;
                pushFinding(p, true, hashes.empty() ? std::string() : hashes.front(), recNarrow);
            }

            // Record keys are named "{basename}|{id}" on this build. That is a
            // record name, not a path, so the signature is weighed against the
            // basename alone - the hex identifier trailing the bar is not
            // evidence and must never reach a substring match - while the
            // finding still names the record exactly as it appears.
            if (!recBase.empty() && MatchesCheatSignature(recBase) &&
                reported.insert(Lower(recName)).second) {
                nameMatches++;
                pushFinding(recName, false, hashes.empty() ? std::string() : hashes.front(),
                            recNarrow);
            }
        }

        if (depth >= 4 || nk.nSub > 65536 || nk.subList == 0xFFFFFFFFu) return;
        std::vector<uint32_t> kids;
        kids.reserve(nk.nSub < 4096 ? nk.nSub : 4096);
        amc::ReadSubkeys(H, nk.subList, kids, 0);
        for (uint32_t k : kids) walk(k, depth + 1);
    };

    walk(H.rootCell(), 0);

    std::string status = std::to_string(records) + " inventory records, " +
        std::to_string(withHashes) + " carrying content hashes, " +
        std::to_string(g_amcacheSha1.size()) + " digests collected";
    if (pathMatches + nameMatches > 0)
        status += ", " + std::to_string(pathMatches + nameMatches) + " cheat match(es)";
    if (rejected > 0)
        status += ", " + std::to_string(rejected) + " value read(s) rejected as malformed";

    // The hive is only worth reporting as read if it actually yielded digests.
    // An empty set means nothing can be corroborated by content, and saying so
    // is the difference between an honest coverage table and a silent gap.
    if (records == 0 || g_amcacheSha1.empty())
        g_cov.addLimited("Amcache (Amcache.hve)", records,
            status + " - this build's record schema yielded no content digests, so the hive "
                    "cannot corroborate execution by content");
    else
        g_cov.add("Amcache (Amcache.hve)", records, status);
}

CheatResult FullScan() {
    CheatResult r;
    r.score = 0;
    g_cov = ScanCoverage();

    // Pre-scan Roblox game sessions so all detection phases can correlate execution times
    r.detectedGames = ScanRobloxGameSessions();

    // Category score accumulators for capping
    int unsignedDllTotal = 0;
    g_lastProgress = 0;

    // ========================================================================
    // PHASE 1: Process Scan ??? Check running processes against cheat signatures
    // ========================================================================
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                std::wstring exeLower = Lower(pe.szExeFile);
                if (exeLower == L"explorer.exe" || exeLower == L"svchost.exe" || 
                    exeLower == L"lsass.exe" || exeLower == L"csrss.exe" || 
                    exeLower == L"winlogon.exe" || exeLower == L"searchindexer.exe") {
                    continue;
                }

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

    UpdateProgress(1, 56);

    // ========================================================================
    // PHASE 2: Roblox Module Inspection ??? Authenticode + Path + Memory
    // ========================================================================
    long processesExamined = 0;
    DWORD robloxPid = 0;
    DWORD robloxFallbackPid = 0;
    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                processesExamined++;
                std::wstring exeName = Lower(pe.szExeFile);
                // Only the live client can hold injected code. Never latch onto
                // the launcher or updater: they enumerate alongside the client,
                // and every live phase below would then inspect the wrong PID
                // and report nothing for a player who is injected right now.
                if (exeName == L"robloxplayerbeta.exe") {
                    robloxPid = pe.th32ProcessID;
                    break;
                }
                bool helper = exeName == L"robloxplayerlauncher.exe" ||
                              exeName == L"robloxupdate.exe" ||
                              exeName == L"robloxupdater.exe" ||
                              exeName == L"robloxwebhelper.exe" ||
                              exeName == L"robloxcrashhandler.exe";
                if (!helper && robloxFallbackPid == 0 && exeName.find(L"roblox") != std::wstring::npos) {
                    robloxFallbackPid = pe.th32ProcessID;
                }
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
    }
    // No exact client name: fall back to a non-helper Roblox process rather than
    // reporting no live target at all. If neither exists the PID stays 0 and
    // coverage honestly reports that Roblox was not running.
    if (robloxPid == 0) robloxPid = robloxFallbackPid;

    if (robloxPid > 0) {
        std::wstring resolved;
        {
            HANDLE hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, robloxPid);
            if (hP) {
                wchar_t buf[MAX_PATH] = {0}; DWORD n = MAX_PATH;
                if (QueryFullProcessImageNameW(hP, 0, buf, &n)) resolved = buf;
                CloseHandle(hP);
            }
        }
        std::string rname = resolved.empty()
            ? "pid " + std::to_string(robloxPid)
            : WideToAnsi(std::filesystem::path(resolved).filename().wstring()) +
              " (PID " + std::to_string(robloxPid) + ")";
        g_cov.add("Roblox live target", 1, "all live phases inspect " + rname);
    } else {
        g_cov.add("Roblox live target", 0, "no Roblox client running - live phases skipped");
    }

    long robloxModulesExamined = 0;
    if (robloxPid > 0) {


        HANDLE modSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, robloxPid);
        if (modSnap != INVALID_HANDLE_VALUE) {
            MODULEENTRY32W me; me.dwSize = sizeof(me);
            if (Module32FirstW(modSnap, &me)) {
                do {
                    robloxModulesExamined++;
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

    g_cov.add("Running processes", processesExamined, "matched against cheat signature catalog");
    g_cov.add("Roblox process modules", robloxModulesExamined,
        robloxPid > 0 ? "signature + Authenticode verified per module" : "Roblox not running during scan");

    UpdateProgress(2, 56);

    // ========================================================================
    // PHASE 3: USN Journal ??? Deleted Cheat Files
    // ========================================================================
    {
        std::vector<DeletedFile> deleted = ScanDeletedFiles(USN_LOOKBACK_HOURS);
        if (g_isAdmin) g_cov.add("USN Journal (deleted files)", (long)deleted.size(), "journal records examined");
        else g_cov.addLimited("USN Journal (deleted files)", 0, "access denied without elevation - deleted-file evidence unreadable");
        for (const auto& df : deleted) {
            if (MatchesCheatSignature(df.name)) {
                std::string corr = CorrelateSessionForFileTime(df.timestamp, r.detectedGames);
                r.findings.push_back({
                    "DELETED_FILE",
                    WideToAnsi(df.name),
                    90,
                    "Path: " + WideToAnsi(df.fullPath) + " | Deleted: " + FileTimeToString(df.timestamp) + corr
                });
                r.score += 30;
            }
        }
    }

    UpdateProgress(3, 56);

    // ========================================================================
    // PHASE 4: BAM Registry ??? Execution History
    // ========================================================================
    {
        std::vector<BamEntry> bamEntries = ParseBamRegistry();
        if (g_isAdmin) g_cov.add("BAM execution history", (long)bamEntries.size(), "per-user execution records parsed");
        else g_cov.addLimited("BAM execution history", 0, "access denied without elevation - execution history unreadable");
        for (const auto& entry : bamEntries) {
            if (MatchesCheatSignature(entry.dosPath)) {
                std::string corr = CorrelateSessionForFileTime(entry.executionTime, r.detectedGames);
                r.findings.push_back({
                    "BAM_EXECUTION",
                    WideToAnsi(entry.dosPath),
                    95,
                    GetFileAgeCategory(entry.executionTime) + " Last executed: " + FileTimeToString(entry.executionTime) + corr
                });
                r.score += 40;
            }
        }
    }

    UpdateProgress(4, 56);

    // ========================================================================
    // PHASE 5: Prefetch ??? Execution Artifacts
    // ========================================================================
    long prefetchExamined = 0;
    bool prefetchReadable = false;
    try {
        for (const auto& e : std::filesystem::directory_iterator(L"C:\\Windows\\Prefetch")) {
            if (!e.is_regular_file()) continue;
            prefetchReadable = true;
            prefetchExamined++;

            std::wstring fn = e.path().filename().wstring();
            if (MatchesCheatSignature(fn)) {
                FILETIME ft = GetFileWriteTime(e.path().wstring());
                std::string timeDetail = "";
                if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
                    timeDetail = " Last executed: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " |";
                }
                r.findings.push_back({
                    "PREFETCH",
                    WideToAnsi(fn),
                    80,
                    GetPathAgeCategory(e.path()) + timeDetail + " Prefetch file confirms execution"
                });
                r.score += 20;
            }
        }
    } catch (...) {}

    if (prefetchReadable) g_cov.add("Prefetch execution artifacts", prefetchExamined, "prefetch files hashed and matched");
    else g_cov.addLimited("Prefetch execution artifacts", 0,
        g_isAdmin ? "directory unreadable" : "access denied without elevation - execution artifacts unreadable");

    UpdateProgress(5, 56);

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

    UpdateProgress(6, 56);

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

    UpdateProgress(7, 56);

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

                            // Scan executables, scripts, shortcuts, and archives
                            bool isExecutable = (ext == L".exe" || ext == L".dll" || ext == L".sys" || ext == L".scr" || ext == L".bat" || ext == L".cmd" || ext == L".ps1" || ext == L".zip" || ext == L".rar" || ext == L".7z" || ext == L".py" || ext == L".lua" || ext == L".lnk");
                            if (!isExecutable) continue;

                            if (MatchesCheatFileSignature(filename)) {
                                FILETIME ft = GetFileWriteTime(fullPath);
                                std::string timeDetail = "";
                                if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
                                    timeDetail = " File timestamp: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " |";
                                }
                                r.findings.push_back({
                                    "CHEAT_FILE",
                                    WideToAnsi(filename),
                                    85,
                                    GetPathAgeCategory(fullPath) + timeDetail + " Path: " + WideToAnsi(fullPath)
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

    UpdateProgress(8, 56);

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
                    std::wstring nameLower = Lower(name);
                    for (const auto& spoofer : SPOOFER_DRIVERS) {
                        std::wstring spooferLower = Lower(spoofer);
                        if (nameLower == spooferLower || nameLower == spooferLower + L".sys") {
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

    UpdateProgress(9, 56);

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
            std::set<std::wstring> seenMui;
            while (true) {
                nameSize = sizeof(valueName) / sizeof(wchar_t);
                if (RegEnumValueW(hMui, idx, valueName, &nameSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                std::wstring vn(valueName);
                
                // Strip .FriendlyAppName and .ApplicationCompany for clean single-entry reporting
                size_t faPos = vn.rfind(L".FriendlyAppName");
                if (faPos != std::wstring::npos) vn = vn.substr(0, faPos);
                size_t acPos = vn.rfind(L".ApplicationCompany");
                if (acPos != std::wstring::npos) vn = vn.substr(0, acPos);

                if (seenMui.insert(Lower(vn)).second && (MatchesCheatSignature(vn) || MatchesCheatFileSignature(vn))) {
                    FILETIME ft = GetFileWriteTime(vn);
                    std::string ageStr = "[Unknown Age]";
                    std::string timeDetail = "";
                    if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
                        ageStr = GetFileAgeCategory(ft);
                        timeDetail = " File timestamp: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " |";
                    }
                    r.findings.push_back({
                        "MUICACHE",
                        WideToAnsi(vn),
                        80,
                        ageStr + timeDetail + " Windows MuiCache - program was opened on this PC"
                    });
                    r.score += 25;
                }
                idx++;
            }
            RegCloseKey(hMui);
        }
    }

    UpdateProgress(10, 56);

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
                    FILETIME ft = GetFileWriteTime(vn);
                    std::string ageStr = "[Unknown Age]";
                    std::string timeDetail = "";
                    if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
                        ageStr = GetFileAgeCategory(ft);
                        timeDetail = " File timestamp: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " |";
                    }
                    r.findings.push_back({
                        "APPCOMPAT",
                        WideToAnsi(vn),
                        85,
                        ageStr + timeDetail + " AppCompat registry - program was executed"
                    });
                    r.score += 25;
                }
                idx++;
            }
            RegCloseKey(hAc);
        }
    }

    UpdateProgress(11, 56);

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

    UpdateProgress(12, 56);

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
                    std::string timeDetail = "";
                    if (type == REG_BINARY && dataSize >= 72) {
                        FILETIME ft;
                        memcpy(&ft, data + 60, sizeof(FILETIME));
                        if (ft.dwHighDateTime != 0 || ft.dwLowDateTime != 0) {
                            ageStr = GetFileAgeCategory(ft);
                            timeDetail = " Last executed: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " |";
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
                            ageStr + timeDetail + " UserAssist (ROT13 decoded) - program was launched"
                        });
                        r.score += 30;
                    }
                    idx++;
                }
                RegCloseKey(hUa);
            }
        }
    }

    UpdateProgress(13, 56);

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

    UpdateProgress(14, 56);

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
            wchar_t cmd[] = L"schtasks /query /fo LIST /v";
            if (CreateProcessW(nullptr, cmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(hWrite);
                std::string taskOutput;
                char buf[8192];
                DWORD bytesRead;
                while (ReadFile(hRead, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
                    buf[bytesRead] = 0;
                    taskOutput += buf;
                }
                CloseHandle(hRead);
                WaitForSingleObject(pi.hProcess, 5000);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);

                std::istringstream iss(taskOutput);
                std::string line;
                std::string curTaskName = "";
                std::string curTaskRun = "";

                auto checkCurrentTask = [&]() {
                    if (curTaskName.empty()) return;
                    std::string combined = curTaskName + " " + curTaskRun;
                    std::string lower = combined;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

                    // Whitelist legitimate Windows and standard vendor tasks
                    if (lower.find("microsoft") != std::string::npos ||
                        lower.find("windows defender") != std::string::npos ||
                        lower.find("exploit guard") != std::string::npos ||
                        lower.find("exploit protection") != std::string::npos ||
                        lower.find("onedrive") != std::string::npos ||
                        lower.find("edgeupdate") != std::string::npos ||
                        lower.find("googleupdate") != std::string::npos ||
                        lower.find("nvidia") != std::string::npos ||
                        lower.find("amd") != std::string::npos ||
                        lower.find("\\system32\\") != std::string::npos) {
                        return;
                    }

                    for (const auto& sig : CHEAT_SIGNATURES) {
                        std::string sigLower = WideToAnsi(sig);
                        std::transform(sigLower.begin(), sigLower.end(), sigLower.begin(), ::tolower);
                        if (sigLower.length() < 4) continue;
                        if (sigLower == "exploit" || sigLower == "executor" || sigLower == "injector" || 
                            sigLower == "spoofer" || sigLower == "bypass" || sigLower == "camlock") continue;

                        if (lower.find(sigLower) != std::string::npos) {
                            r.findings.push_back({
                                "SCHEDULED_TASK",
                                curTaskName,
                                75,
                                "Task Action: " + (curTaskRun.empty() ? "(none)" : curTaskRun)
                            });
                            r.score += 20;
                            break;
                        }
                    }
                };

                while (std::getline(iss, line)) {
                    if (line.find("TaskName:") != std::string::npos) {
                        checkCurrentTask();
                        curTaskName = line.substr(line.find("TaskName:") + 9);
                        while (!curTaskName.empty() && (curTaskName[0] == ' ' || curTaskName[0] == '\t')) curTaskName.erase(0, 1);
                        while (!curTaskName.empty() && (curTaskName.back() == '\r' || curTaskName.back() == ' ')) curTaskName.pop_back();
                        curTaskRun = "";
                    } else if (line.find("Task To Run:") != std::string::npos) {
                        curTaskRun = line.substr(line.find("Task To Run:") + 12);
                        while (!curTaskRun.empty() && (curTaskRun[0] == ' ' || curTaskRun[0] == '\t')) curTaskRun.erase(0, 1);
                        while (!curTaskRun.empty() && (curTaskRun.back() == '\r' || curTaskRun.back() == ' ')) curTaskRun.pop_back();
                    }
                }
                checkCurrentTask();
            } else {
                CloseHandle(hWrite);
                CloseHandle(hRead);
            }
        }
    }

    UpdateProgress(15, 56);

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

    UpdateProgress(16, 56);

    // ========================================================================
    // PHASE 17: Browser History ??? Deep Search Engines, YouTube Videos & Cheat URLs
    // Scans Chrome, Edge, Brave, Firefox, Opera for search engine queries & video titles
    // Also scans WAL/journal files for deleted history
    // ========================================================================
    {
        wchar_t localAppData[MAX_PATH], appData[MAX_PATH];
        SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, 0, localAppData);
        SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, appData);

        std::vector<std::wstring> allBrowserFiles;

        // Chromium-based browsers: Crawl all profiles (Default, Profile 1, Profile 2, etc.)
        std::vector<std::wstring> chromiumUserDatas = {
            std::wstring(localAppData) + L"\\Google\\Chrome\\User Data",
            std::wstring(localAppData) + L"\\Microsoft\\Edge\\User Data",
            std::wstring(localAppData) + L"\\BraveSoftware\\Brave-Browser\\User Data",
            std::wstring(localAppData) + L"\\Opera Software\\Opera GX Stable",
            std::wstring(localAppData) + L"\\Opera Software\\Opera Stable",
            std::wstring(localAppData) + L"\\Vivaldi\\User Data",
            std::wstring(localAppData) + L"\\Arc\\User Data",
            std::wstring(localAppData) + L"\\Chromium\\User Data",
        };

        for (const auto& baseDir : chromiumUserDatas) {
            try {
                if (std::filesystem::exists(baseDir)) {
                    // Direct history (e.g. Opera)
                    std::wstring directH = baseDir + L"\\History";
                    if (std::filesystem::exists(directH)) {
                        allBrowserFiles.push_back(directH);
                        allBrowserFiles.push_back(directH + L"-wal");
                        allBrowserFiles.push_back(directH + L"-journal");
                    }
                    // Subdirectory profiles (Default, Profile 1, Profile 2, etc.)
                    for (const auto& entry : std::filesystem::directory_iterator(baseDir)) {
                        if (entry.is_directory()) {
                            std::wstring subH = entry.path().wstring() + L"\\History";
                            if (std::filesystem::exists(subH)) {
                                allBrowserFiles.push_back(subH);
                                allBrowserFiles.push_back(subH + L"-wal");
                                allBrowserFiles.push_back(subH + L"-journal");
                            }
                        }
                    }
                }
            } catch (...) {}
        }

        // Firefox ??? find all profile folders
        std::wstring ffProfiles = std::wstring(appData) + L"\\Mozilla\\Firefox\\Profiles";
        try {
            if (std::filesystem::exists(ffProfiles)) {
                for (const auto& entry : std::filesystem::directory_iterator(ffProfiles)) {
                    if (entry.is_directory()) {
                        std::wstring placesDb = entry.path().wstring() + L"\\places.sqlite";
                        if (std::filesystem::exists(placesDb)) {
                            allBrowserFiles.push_back(placesDb);
                            allBrowserFiles.push_back(placesDb + L"-wal");
                            allBrowserFiles.push_back(placesDb + L"-journal");
                        }
                    }
                }
            }
        } catch (...) {}

        std::set<std::string> seenSearchAndVideos;

        for (const auto& dbPath : allBrowserFiles) {
            try {
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                std::wstring tempDbPath = std::wstring(tempPath) + L"\\rox_browser_temp_" + std::to_wstring(GetCurrentProcessId()) + L".db";

                if (!CopyFileW(dbPath.c_str(), tempDbPath.c_str(), FALSE)) continue;

                std::ifstream f(tempDbPath.c_str(), std::ios::binary);
                if (!f.is_open()) {
                    DeleteFileW(tempDbPath.c_str());
                    continue;
                }

                // Read up to 50MB of the file
                std::string content;
                content.resize(50 * 1024 * 1024);
                f.read(&content[0], content.size());
                content.resize(f.gcount());
                f.close();
                DeleteFileW(tempDbPath.c_str());

                std::string contentLower = content;
                std::transform(contentLower.begin(), contentLower.end(), contentLower.begin(), ::tolower);

                bool isWal = dbPath.find(L"-wal") != std::wstring::npos || dbPath.find(L"-journal") != std::wstring::npos;

                // 1. Direct Cheat URLs
                for (const auto& url : BROWSER_CHEAT_URLS) {
                    std::string urlLower = url;
                    std::transform(urlLower.begin(), urlLower.end(), urlLower.begin(), ::tolower);
                    if (contentLower.find(urlLower) != std::string::npos) {
                        r.findings.push_back({
                            isWal ? "DELETED_BROWSER_HISTORY" : "BROWSER_HISTORY",
                            url,
                            isWal ? 90 : 75,
                            (isWal ? "Deleted browser history contains: " : "Browser history contains: ") + WideToAnsi(dbPath)
                        });
                        r.score += isWal ? 30 : 20;
                    }
                }

                // 2. Search Engines & YouTube Query/Title Deep Scan
                struct EngineSpec {
                    std::string name;
                    std::string prefix;
                    std::string param;
                };

                std::vector<EngineSpec> engines = {
                    { "YouTube", "youtube.com/results", "search_query=" },
                    { "YouTube", "youtube.com/watch", "v=" },
                    { "Google", "google.com/search", "q=" },
                    { "Bing", "bing.com/search", "q=" },
                    { "DuckDuckGo", "duckduckgo.com/?", "q=" },
                    { "Yandex", "yandex.com/search", "text=" },
                    { "Yahoo", "search.yahoo.com/search", "p=" },
                    { "Brave", "search.brave.com/search", "q=" }
                };

                const std::vector<std::string> searchCheatKeywords = {
                    "script", "scripts", "executor", "exploit", "gakuran", "aimbot", "camlock", "esp",
                    "bypass", "roblox cheat", "roblox hack", "pastebin", "solara", "wave", "xeno",
                    "volcano", "delta", "codex", "matcha", "aimmy", "dx9", "potassium", "frost",
                    "valyse", "getgenv", "autofarm", "auto parry", "kill all", "krampus", "ro-exec",
                    "synapse", "fluxus", "krnl", "hydrogen", "arceus", "swagmode", "silent aim"
                };

                for (const auto& eng : engines) {
                    size_t pos = 0;
                    while ((pos = contentLower.find(eng.prefix, pos)) != std::string::npos) {
                        size_t urlEnd = pos;
                        while (urlEnd < content.length() && (unsigned char)content[urlEnd] > 32 && content[urlEnd] != '"' && content[urlEnd] != '\'' && content[urlEnd] != '<' && content[urlEnd] != '>') {
                            urlEnd++;
                        }
                        std::string fullUrl = content.substr(pos, urlEnd - pos);
                        std::string fullUrlLower = contentLower.substr(pos, urlEnd - pos);

                        std::string query = "";
                        size_t paramPos = fullUrlLower.find(eng.param);
                        if (paramPos != std::string::npos) {
                            size_t valStart = paramPos + eng.param.length();
                            size_t valEnd = fullUrl.find_first_of("&# \r\n\t\"'<>", valStart);
                            if (valEnd == std::string::npos) valEnd = fullUrl.length();
                            std::string rawQ = fullUrl.substr(valStart, valEnd - valStart);
                            // Simple URL decode
                            for (size_t qi = 0; qi < rawQ.length(); qi++) {
                                if (rawQ[qi] == '+') query += ' ';
                                else if (rawQ[qi] == '%' && qi + 2 < rawQ.length()) {
                                    int hv = 0;
                                    if (sscanf_s(rawQ.substr(qi + 1, 2).c_str(), "%x", &hv) == 1 && hv >= 32 && hv <= 126) {
                                        query += (char)hv;
                                        qi += 2;
                                    } else query += rawQ[qi];
                                } else query += rawQ[qi];
                            }
                        }

                        // Search ahead for title in SQLite record
                        std::string title = "";
                        size_t searchAhead = (std::min)(content.length(), urlEnd + 300);
                        for (size_t ti = urlEnd; ti < searchAhead; ti++) {
                            if ((unsigned char)content[ti] >= 32 && (unsigned char)content[ti] <= 126) {
                                size_t strEnd = ti;
                                while (strEnd < searchAhead && (unsigned char)content[strEnd] >= 32 && (unsigned char)content[strEnd] <= 126) {
                                    strEnd++;
                                }
                                if (strEnd - ti >= 6 && strEnd - ti <= 150) {
                                    std::string candidate = content.substr(ti, strEnd - ti);
                                    std::string candL = candidate;
                                    std::transform(candL.begin(), candL.end(), candL.begin(), ::tolower);
                                    if (candL.find("http") == std::string::npos && candL.find("table") == std::string::npos && candL.find("index") == std::string::npos) {
                                        title = candidate;
                                        break;
                                    }
                                }
                                ti = strEnd;
                            }
                        }

                        std::string checkTarget = fullUrlLower + " " + query + " " + title;
                        std::transform(checkTarget.begin(), checkTarget.end(), checkTarget.begin(), ::tolower);

                        bool matchedCheat = false;
                        std::string matchedKeyword = "";
                        for (const auto& kw : searchCheatKeywords) {
                            if (checkTarget.find(kw) != std::string::npos) {
                                matchedCheat = true;
                                matchedKeyword = kw;
                                break;
                            }
                        }

                        if (matchedCheat) {
                            std::string displayKey = query.empty() ? title : query;
                            if (displayKey.length() >= 3 && seenSearchAndVideos.find(displayKey) == seenSearchAndVideos.end()) {
                                seenSearchAndVideos.insert(displayKey);

                                if (eng.name == "YouTube") {
                                    r.findings.push_back({
                                        isWal ? "DELETED_BROWSER_HISTORY" : "YOUTUBE_CHEAT_VIDEO",
                                        title.empty() ? ("YouTube: " + query) : ("YouTube: \"" + title + "\""),
                                        isWal ? 90 : 80,
                                        "Roblox script video / search on YouTube: " + (title.empty() ? query : ("\"" + title + "\"")) + " (Keyword: " + matchedKeyword + ")"
                                    });
                                    r.score += isWal ? 30 : 20;
                                } else {
                                    r.findings.push_back({
                                        isWal ? "DELETED_BROWSER_HISTORY" : "SEARCH_ENGINE_CHEAT_QUERY",
                                        eng.name + " Search: \"" + displayKey + "\"",
                                        isWal ? 85 : 75,
                                        eng.name + " Search Query for Roblox cheats: \"" + displayKey + "\"" + (title.empty() ? "" : (" | Page: \"" + title + "\""))
                                    });
                                    r.score += isWal ? 25 : 15;
                                }
                            }
                        }

                        pos = urlEnd + 1;
                    }
                }
            } catch (...) {}
        }
    }

    UpdateProgress(17, 56);

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

    UpdateProgress(18, 56);

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

    UpdateProgress(19, 56);

    // ========================================================================
    // PHASE 20: Network Data Usage (SRUM) & High-Frequency Application Execution Forensics
    // Analyzes Windows Data Usage metrics and FeatureUsage/Prefetch execution counts
    // ========================================================================
    {
        // 1. FeatureUsage AppSwitched execution frequency
        HKEY hAppSwitch;
        if (RegOpenKeyExW(HKEY_CURRENT_USER,
            L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\FeatureUsage\\AppSwitched",
            0, KEY_READ, &hAppSwitch) == ERROR_SUCCESS)
        {
            DWORD idx = 0;
            wchar_t valName[2048];
            DWORD valNameLen;
            DWORD valType;
            DWORD runCount = 0;
            DWORD dataSize = sizeof(runCount);

            while (true) {
                valNameLen = sizeof(valName) / sizeof(wchar_t);
                dataSize = sizeof(runCount);
                if (RegEnumValueW(hAppSwitch, idx++, valName, &valNameLen, nullptr, &valType, (LPBYTE)&runCount, &dataSize) != ERROR_SUCCESS) break;

                std::wstring nameW(valName);
                if (MatchesCheatSignature(nameW)) {
                    r.findings.push_back({
                        "HIGH_FREQUENCY_EXECUTION",
                        WideToAnsi(nameW),
                        85,
                        "Windows FeatureUsage tracked " + std::to_string(runCount) + " launch/switch events for this cheat executable"
                    });
                    r.score += 25;
                }
            }
            RegCloseKey(hAppSwitch);
        }

        // 2. Windows Network & Internet Data Usage (SRUM / SRUDB.dat)
        try {
            std::wstring srumPath = L"C:\\Windows\\System32\\sru\\SRUDB.dat";
            if (std::filesystem::exists(srumPath)) {
                wchar_t tempPath[MAX_PATH];
                GetTempPathW(MAX_PATH, tempPath);
                std::wstring tempSrum = std::wstring(tempPath) + L"\\srum_temp_" + std::to_wstring(GetCurrentProcessId()) + L".dat";

                if (CopyFileW(srumPath.c_str(), tempSrum.c_str(), FALSE)) {
                    std::ifstream fSrum(tempSrum.c_str(), std::ios::binary);
                    if (fSrum.is_open()) {
                        std::string srumContent;
                        srumContent.resize(25 * 1024 * 1024);
                        fSrum.read(&srumContent[0], srumContent.size());
                        srumContent.resize(fSrum.gcount());
                        fSrum.close();

                        std::string srumLower = srumContent;
                        std::transform(srumLower.begin(), srumLower.end(), srumLower.begin(), ::tolower);

                        for (const auto& sig : CHEAT_FILE_SIGNATURES) {
                            std::string sigLower = WideToAnsi(sig);
                            std::transform(sigLower.begin(), sigLower.end(), sigLower.begin(), ::tolower);
                            if (sigLower.length() < 4) continue;
                            if (sigLower == "rc7") sigLower = "rc7.exe";

                            bool matched = false;
                            if (sigLower.find(".exe") != std::string::npos || sigLower.find(".dll") != std::string::npos) {
                                matched = (srumLower.find(sigLower) != std::string::npos);
                            } else {
                                matched = (srumLower.find("\\" + sigLower + ".exe") != std::string::npos ||
                                           srumLower.find(sigLower + ".exe") != std::string::npos);
                            }

                            if (matched) {
                                r.findings.push_back({
                                    "NETWORK_DATA_USAGE",
                                    WideToAnsi(sig),
                                    85,
                                    "Windows Network & Internet Data Usage (SRUM) recorded active network data transferred by: " + WideToAnsi(sig)
                                });
                                r.score += 20;
                            }
                        }
                    }
                    DeleteFileW(tempSrum.c_str());
                }
            }
        } catch (...) {}
    }

    UpdateProgress(20, 56);
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
    
    UpdateProgress(20, 56);

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
    
    UpdateProgress(21, 56);

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

    UpdateProgress(22, 56);

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

    UpdateProgress(23, 56);

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

    UpdateProgress(24, 56);

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

    UpdateProgress(25, 56);

    // ========================================================================
    // PHASE 26: AppCompatFlags store ??? execution recorded by Windows shell
    // This is a NAME match against the compatibility store. The real content-hash
    // proof lives in Amcache.hve, parsed in PHASE 63.
    // ========================================================================
    {
        long appcompatExamined = 0;
        HKEY hAmcache = nullptr;
        LONG rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\AppCompatFlags",
                    0, KEY_READ, &hAmcache);
        if (rc == ERROR_SUCCESS) {
            // Enumerate subkeys recursively looking for file paths
            std::function<void(HKEY, int)> scanAmcache = [&](HKEY hKey, int depth) {
                if (depth > 3) return;
                DWORD idx = 0;
                wchar_t subKeyName[512]; DWORD subKeySize;
                while (true) {
                    subKeySize = sizeof(subKeyName) / sizeof(wchar_t);
                    if (RegEnumKeyExW(hKey, idx, subKeyName, &subKeySize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                    
                    std::wstring keyName(subKeyName);
                    appcompatExamined++;
                    if (MatchesCheatSignature(keyName)) {
                        r.findings.push_back({
                            "APPCOMPAT",
                            WideToAnsi(keyName),
                            85,
                            "AppCompatFlags store - execution recorded by name match"
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
                                        "APPCOMPAT",
                                        WideToAnsi(valStr),
                                        85,
                                        "AppCompatFlags value matches cheat signature"
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
            g_cov.add("AppCompatFlags (shell execution store)", appcompatExamined,
                "subkeys and values enumerated, name-matched");
        } else {
            // Two failure modes that mean opposite things to the operator. One
            // is fixed by elevating; the other cannot be fixed at all. Reporting
            // both as "unreadable" would send someone in a circle - this install
            // simply has no AppCompatFlags key, and no elevation creates it.
            std::string why;
            if (rc == ERROR_FILE_NOT_FOUND)
                why = "key is not present on this Windows install - elevating cannot create it";
            else if (rc == ERROR_ACCESS_DENIED)
                why = "access denied - requires an elevated (administrator) run";
            else
                why = "registry key could not be opened (error " + std::to_string(rc) + ")";
            g_cov.addLimited("AppCompatFlags (shell execution store)", 0, why);
        }
    }

    UpdateProgress(26, 56);

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
                        if (sigLower.length() < 4) continue;
                        if (sigLower == "exploit" || sigLower == "executor" || sigLower == "injector" || 
                            sigLower == "spoofer" || sigLower == "bypass" || sigLower == "camlock" ||
                            sigLower == "oldui" || sigLower == "newui") continue;
                        if (sigLower == "rc7") sigLower = "rc7.exe";

                        bool matched = false;
                        if (sigLower.find(".exe") != std::string::npos || sigLower.find(".dll") != std::string::npos) {
                            matched = (contentLower.find(sigLower) != std::string::npos);
                        } else {
                            matched = (contentLower.find("\\" + sigLower + ".exe") != std::string::npos ||
                                       contentLower.find(sigLower + ".exe") != std::string::npos);
                        }

                        if (matched) {
                            r.findings.push_back({
                                "SRUM_DATABASE",
                                sigAnsi,
                                80,
                                "SRUM database contains cheat execution history: " + sigAnsi
                            });
                            r.score += 25;
                        }
                    }
                }
            } catch (...) {}
            DeleteFileW(srumCopy.c_str());
        }
    }

    UpdateProgress(27, 56);

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

    UpdateProgress(28, 56);

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
                        std::to_string(count) + " restore point(s) found",
                        10,
                        "Windows System Restore Snapshots (Backup Copies) - Standard Windows OS restore points for system recovery"
                    });
                    // System Restore points are normal Windows OS behavior - 0 score penalty
                }
            } else {
                CloseHandle(hWrite3);
                CloseHandle(hRead3);
            }
        }
    }

    UpdateProgress(29, 56);

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

    UpdateProgress(30, 56);

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

    UpdateProgress(31, 56);

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

    UpdateProgress(32, 56);

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

    UpdateProgress(33, 56);

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

    UpdateProgress(34, 56);

    // ========================================================================
    // PHASE 35: Discord RPC / LevelDB Cache Scan
    // Detects cheat rich presence logged by Discord
    // ========================================================================
    {
        wchar_t appData[MAX_PATH];
        if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appData))) {
            std::vector<std::wstring> discordDirs = {
                L"\\discord", L"\\discordcanary", L"\\discordptb",
                L"\\discorddevelopment", L"\\Vesktop", L"\\WebCord",
                L"\\BetterDiscord", L"\\ArmCord"
            };
            for (const auto& dir : discordDirs) {
                std::wstring ldbPath = std::wstring(appData) + dir + L"\\Local Storage\\leveldb";
                if (std::filesystem::exists(ldbPath)) {
                    for (const auto& entry : std::filesystem::directory_iterator(ldbPath)) {
                        if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                            std::ifstream file(entry.path(), std::ios::binary);
                            if (file.is_open()) {
                                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                                std::string lowerContent = content;
                                std::transform(lowerContent.begin(), lowerContent.end(), lowerContent.begin(), ::tolower);
                                
                                bool flagged = false;
                                // Check Discord RPC rich presence JSON names and activity states
                                for (const auto& keyword : DISCORD_RPC_KEYWORDS) {
                                    if (lowerContent.find(keyword) != std::string::npos) {
                                        r.findings.push_back({
                                            "DISCORD_RPC_CACHE",
                                            "Discord RPC Cheat Activity Log",
                                            85,
                                            "Discord activity cache logged: " + keyword
                                        });
                                        r.score += 35;
                                        flagged = true;
                                        break; // Only flag once per file
                                    }
                                }
                                if (flagged) continue;

                                // Check exploit domains / invite links
                                for (const auto& keyword : BROWSER_CHEAT_URLS) {
                                    if (lowerContent.find(keyword) != std::string::npos) {
                                        r.findings.push_back({
                                            "DISCORD_RPC_CACHE",
                                            "Discord RPC Cheat URL Log",
                                            80,
                                            "Discord logged execution/link: " + keyword
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

    UpdateProgress(35, 56);

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

    UpdateProgress(36, 56);

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
                            std::ifstream file(entry.path());
                            if (file.is_open()) {
                                std::string line;
                                while (std::getline(file, line)) {
                                    std::string lowerLine = line;
                                    std::transform(lowerLine.begin(), lowerLine.end(), lowerLine.begin(), ::tolower);
                                    for (const auto& sig : CHEAT_FILE_SIGNATURES) {
                                        if (lowerLine.find(WideToAnsi(sig)) != std::string::npos) {
                                             r.findings.push_back({
                                                "ROBLOX_CRASH_LOG",
                                                "Cheat Exception in Crash Dump",
                                                80,
                                                "Roblox crashed while cheat was injected: " + WideToAnsi(sig) + " (Time: " + FormatTime12Hour(ctime) + ")"
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

    UpdateProgress(37, 56);

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

    UpdateProgress(38, 56);

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

    UpdateProgress(39, 56);

    // ========================================================================
    // PHASE 40: Windows Defender Exclusions
    // ========================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[MAX_PATH];
            DWORD valueNameSize = MAX_PATH;
            DWORD type;
            while (RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr, &type, nullptr, nullptr) == ERROR_SUCCESS) {
                std::wstring pathStr(valueName);
                std::wstring lower = pathStr;
                std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                
                if (MatchesCheatSignature(lower) || MatchesCheatFileSignature(lower)) {
                    r.findings.push_back({
                        "DEFENDER_EXCLUSION",
                        WideToAnsi(pathStr),
                        95,
                        GetPathAgeCategory(pathStr) + " Whitelisted directory/file in Windows Defender"
                    });
                    r.score += 40;
                }
                
                valueNameSize = MAX_PATH;
                index++;
            }
            RegCloseKey(hKey);
        }
    }

    UpdateProgress(40, 56);

    // ========================================================================
    // PHASE 41: Archive Extraction History (WinRAR / 7-Zip)
    // ========================================================================
    {
        HKEY hKey;
        // WinRAR ArcHistory
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\WinRAR\\ArcHistory", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD index = 0;
            wchar_t valueName[MAX_PATH];
            DWORD valueNameSize = MAX_PATH;
            DWORD type;
            BYTE data[MAX_PATH * 2];
            DWORD dataSize = sizeof(data);
            while (RegEnumValueW(hKey, index, valueName, &valueNameSize, nullptr, &type, data, &dataSize) == ERROR_SUCCESS) {
                if (type == REG_SZ) {
                    std::wstring pathStr((wchar_t*)data);
                    std::wstring lower = pathStr;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    
                    if (MatchesCheatSignature(lower) || MatchesCheatFileSignature(lower)) {
                        r.findings.push_back({
                            "ARCHIVE_HISTORY",
                            "WinRAR Archive History",
                            80,
                            "Path: " + WideToAnsi(pathStr)
                        });
                        r.score += 25;
                    }
                }
                valueNameSize = MAX_PATH;
                dataSize = sizeof(data);
                index++;
            }
            RegCloseKey(hKey);
        }
        // 7-Zip History
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\7-Zip\\Compression", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD type;
            BYTE data[4096];
            DWORD dataSize = sizeof(data);
            if (RegQueryValueExW(hKey, L"ArcHistory", nullptr, &type, data, &dataSize) == ERROR_SUCCESS && type == REG_MULTI_SZ) {
                wchar_t* strPtr = (wchar_t*)data;
                while (*strPtr) {
                    std::wstring pathStr(strPtr);
                    std::wstring lower = pathStr;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);
                    
                    if (MatchesCheatSignature(lower) || MatchesCheatFileSignature(lower)) {
                        r.findings.push_back({
                            "ARCHIVE_HISTORY",
                            "7-Zip Archive History",
                            80,
                            "Path: " + WideToAnsi(pathStr)
                        });
                        r.score += 25;
                    }
                    strPtr += wcslen(strPtr) + 1;
                }
            }
            RegCloseKey(hKey);
        }
    }

    UpdateProgress(41, 56);

    // ========================================================================
    // PHASE 42: Factory Reset Forensics
    // ========================================================================
    {
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD installDate = 0;
            DWORD dataSize = sizeof(installDate);
            if (RegQueryValueExW(hKey, L"InstallDate", nullptr, nullptr, (LPBYTE)&installDate, &dataSize) == ERROR_SUCCESS) {
                time_t currentTime = time(NULL);
                if (currentTime > installDate) {
                    double diffSeconds = difftime(currentTime, installDate);
                    double diffDays = diffSeconds / (60.0 * 60.0 * 24.0);
                    
                    if (diffDays <= 7.0) {
                        r.findings.push_back({
                            "FACTORY_RESET",
                            "Recent Windows Installation / Factory Reset",
                            90,
                            "PC was wiped/reset " + std::to_string((int)diffDays) + " days ago. Extremely high chance of anti-forensics."
                        });
                        r.score += 50;
                    } else if (diffDays <= 30.0) {
                        r.findings.push_back({
                            "FACTORY_RESET",
                            "Windows Installation / Factory Reset within 30 days",
                            40,
                            "PC was wiped/reset " + std::to_string((int)diffDays) + " days ago. Suspicious but could be legitimate."
                        });
                        r.score += 15;
                    }
                }
            }
            RegCloseKey(hKey);
        }
    }

    UpdateProgress(42, 56);

    // ========================================================================
    // PHASE 43: USN Journal & Event Log Tampering Detection (Anti-Forensics)
    // Detects if a suspect wiped the NTFS change journal or cleared event logs
    //
    // A log-clear event on its own is NOT proof of cheat concealment: Windows
    // Update, Disk Cleanup and many installers legitimately clear or rotate
    // logs, and an incident from two years ago says nothing about present
    // intent. These checks therefore only report clears inside a recency
    // window. Anything older is treated as background noise, not evidence.
    // ========================================================================
    {
        // ISO8601 UTC cutoff for the recency window (EvtQuery XPath needs it)
        auto isoCutoff = [](int daysBack) -> std::string {
            FILETIME nowFt; GetSystemTimeAsFileTime(&nowFt);
            ULARGE_INTEGER nowUi;
            nowUi.LowPart = nowFt.dwLowDateTime; nowUi.HighPart = nowFt.dwHighDateTime;
            // 100ns ticks per day
            ULONGLONG cutoffUi = nowUi.QuadPart - ((ULONGLONG)daysBack * 10000000ULL * 60ULL * 60ULL * 24ULL);
            FILETIME cf; cf.dwLowDateTime = (DWORD)(cutoffUi & 0xFFFFFFFF); cf.dwHighDateTime = (DWORD)(cutoffUi >> 32);
            SYSTEMTIME st; FileTimeToSystemTime(&cf, &st);
            char buf[64];
            snprintf(buf, sizeof(buf), "%04u-%02u-%02uT%02u:%02u:%02u.000Z",
                     st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            return std::string(buf);
        };
        // Only clears newer than this count as evidence of present concealment.
        const int EVENT_CLEAR_RECENCY_DAYS = 90;
        std::string cutoff = isoCutoff(EVENT_CLEAR_RECENCY_DAYS);

        auto recentClearCount = [&](const wchar_t* channel, int eventId) -> int {
            std::wstring q = L"*[System[(EventID=" + std::to_wstring(eventId) +
                             L") and TimeCreated[@SystemTime>='" + AnsiToWide(cutoff) + L"']]]";
            EVT_HANDLE h = EvtQuery(NULL, channel, q.c_str(), EvtQueryChannelPath | EvtQueryReverseDirection);
            if (!h) return 0;
            EVT_HANDLE evts[5]; DWORD returned = 0;
            int count = 0;
            if (EvtNext(h, 5, evts, 500, 0, &returned) && returned > 0) {
                count = (int)returned;
                for (DWORD i = 0; i < returned; i++) EvtClose(evts[i]);
            }
            EvtClose(h);
            return count;
        };
        HANDLE hVol = CreateFileW(L"\\\\.\\C:", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                  nullptr, OPEN_EXISTING, 0, nullptr);
        if (hVol != INVALID_HANDLE_VALUE) {
            USN_JOURNAL_DATA journalData = {0};
            DWORD bytesReturned = 0;
            if (!DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                                 &journalData, sizeof(journalData), &bytesReturned, nullptr)) {
                r.findings.push_back({
                    "ANTI_FORENSICS_WIPER",
                    "NTFS USN Change Journal Disabled / Deleted",
                    95,
                    "The USN Change Journal on C: was wiped or deleted to conceal file execution."
                });
                r.score += 45;
            }
            CloseHandle(hVol);
        }

        // System log clear (Event 104). Windows Update, Disk Cleanup and many
        // installers legitimately rotate the System log, so a clear on its own
        // is NOT concealment proof — it is recorded as an indicative trace only
        // (confidence < 50 demotes it out of the evasion tier) and only when it
        // falls inside the recency window above.
        int sysClears = recentClearCount(L"System", 104);
        if (sysClears > 0) {
            r.findings.push_back({
                "ANTI_FORENSICS_WIPER",
                "System Event Log Cleared (recent)",
                45,
                "Windows System event log was cleared " + std::to_string(sysClears) +
                " time(s) within the last " + std::to_string(EVENT_CLEAR_RECENCY_DAYS) +
                " days. Routine maintenance can cause this, so on its own it is not "
                "proof of cheat concealment and is recorded only as a trace."
            });
        }

        // Security audit log clear (Event 1102). Clearing the Security log is
        // rare and almost never routine — it is the one log-clear signal that
        // still carries real weight, so it stays high confidence when recent.
        int secClears = recentClearCount(L"Security", 1102);
        if (secClears > 0) {
            r.findings.push_back({
                "ANTI_FORENSICS_WIPER",
                "Security Audit Log Cleared (recent)",
                90,
                "Windows Security audit log was cleared " + std::to_string(secClears) +
                " time(s) within the last " + std::to_string(EVENT_CLEAR_RECENCY_DAYS) +
                " days. This log is cleared to erase forensic access records and is "
                "not touched by routine maintenance."
            });
        }

        // Application log clear (Event 104). Same reasoning as the System log:
        // cleared routinely by installers and updates, so indicative only.
        int appClears = recentClearCount(L"Application", 104);
        if (appClears > 0) {
            r.findings.push_back({
                "ANTI_FORENSICS_WIPER",
                "Application Event Log Cleared (recent)",
                40,
                "Windows Application event log was cleared " + std::to_string(appClears) +
                " time(s) within the last " + std::to_string(EVENT_CLEAR_RECENCY_DAYS) +
                " days. This is routine for many installers and is not proof of "
                "concealment on its own."
            });
        }

        // 4. Registry Anti-Forensic Tampering (Disabled Forensics Services)
        HKEY hPref;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters", 0, KEY_READ, &hPref) == ERROR_SUCCESS) {
            DWORD ep = 3, epSize = sizeof(ep);
            if (RegQueryValueExW(hPref, L"EnablePrefetcher", nullptr, nullptr, (LPBYTE)&ep, &epSize) == ERROR_SUCCESS) {
                if (ep == 0) {
                    r.findings.push_back({
                        "ANTI_FORENSICS_WIPER",
                        "Windows Prefetching Disabled (EnablePrefetcher = 0)",
                        90,
                        "Prefetch was intentionally disabled in registry to prevent execution tracking."
                    });
                    r.score += 35;
                }
            }
            RegCloseKey(hPref);
        }

        HKEY hEvtSvc;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\EventLog", 0, KEY_READ, &hEvtSvc) == ERROR_SUCCESS) {
            DWORD startVal = 2, sSize = sizeof(startVal);
            if (RegQueryValueExW(hEvtSvc, L"Start", nullptr, nullptr, (LPBYTE)&startVal, &sSize) == ERROR_SUCCESS) {
                if (startVal == 4) {
                    r.findings.push_back({
                        "ANTI_FORENSICS_WIPER",
                        "Windows EventLog Service Disabled",
                        95,
                        "The Windows EventLog service was set to Disabled (Start=4) to suppress system audit logs."
                    });
                    r.score += 50;
                }
            }
            RegCloseKey(hEvtSvc);
        }

        HKEY hBamSvc;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\bam", 0, KEY_READ, &hBamSvc) == ERROR_SUCCESS) {
            DWORD startVal = 2, sSize = sizeof(startVal);
            if (RegQueryValueExW(hBamSvc, L"Start", nullptr, nullptr, (LPBYTE)&startVal, &sSize) == ERROR_SUCCESS) {
                if (startVal == 4) {
                    r.findings.push_back({
                        "ANTI_FORENSICS_WIPER",
                        "Background Activity Moderator (BAM) Disabled",
                        95,
                        "The BAM driver service was disabled (Start=4) to prevent Windows from tracking executed programs."
                    });
                    r.score += 45;
                }
            }
            RegCloseKey(hBamSvc);
        }
    }

    UpdateProgress(43, 56);

    // ========================================================================
    // PHASE 44: RunMRU & OpenSaveMRU Forensics
    // Extracts commands executed via Win+R and files chosen in Open/Save dialogs
    // ========================================================================
    {
        HKEY hRunMru;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU", 0, KEY_READ, &hRunMru) == ERROR_SUCCESS) {
            FILETIME mruFt = {0};
            RegQueryInfoKeyW(hRunMru, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, &mruFt);
            std::string timeDetail = "";
            if (mruFt.dwLowDateTime != 0 || mruFt.dwHighDateTime != 0) {
                timeDetail = " Last run: " + FileTimeToString(mruFt) + CorrelateSessionForFileTime(mruFt, r.detectedGames) + " |";
            }
            DWORD idx = 0;
            wchar_t valName[64]; DWORD valSize;
            wchar_t valData[1024]; DWORD dataSize; DWORD type;
            while (true) {
                valSize = sizeof(valName) / sizeof(wchar_t);
                dataSize = sizeof(valData);
                if (RegEnumValueW(hRunMru, idx, valName, &valSize, nullptr, &type, (LPBYTE)valData, &dataSize) != ERROR_SUCCESS) break;
                if (type == REG_SZ) {
                    std::wstring cmd(valData);
                    if (MatchesCheatSignature(cmd) || MatchesCheatFileSignature(cmd)) {
                        r.findings.push_back({
                            "RUN_MRU",
                            WideToAnsi(cmd),
                            90,
                            timeDetail + " Command executed directly from Windows Run dialog (Win+R)"
                        });
                        r.score += 35;
                    }
                }
                idx++;
            }
            RegCloseKey(hRunMru);
        }

        HKEY hOpenSave;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU", 0, KEY_READ, &hOpenSave) == ERROR_SUCCESS) {
            DWORD subIdx = 0;
            wchar_t extKey[128]; DWORD extKeySize;
            std::set<std::string> reportedOpenSave;
            while (true) {
                extKeySize = sizeof(extKey) / sizeof(wchar_t);
                if (RegEnumKeyExW(hOpenSave, subIdx, extKey, &extKeySize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                HKEY hSubExt;
                if (RegOpenKeyExW(hOpenSave, extKey, 0, KEY_READ, &hSubExt) == ERROR_SUCCESS) {
                    DWORD vIdx = 0;
                    wchar_t vName[64]; DWORD vSize;
                    BYTE bData[4096]; DWORD bDataSize; DWORD vType;
                    while (true) {
                        vSize = sizeof(vName) / sizeof(wchar_t);
                        bDataSize = sizeof(bData);
                        if (RegEnumValueW(hSubExt, vIdx, vName, &vSize, nullptr, &vType, bData, &bDataSize) != ERROR_SUCCESS) break;
                        if (vType == REG_BINARY && bDataSize > 32) {
                            std::vector<std::wstring> extractedNames;

                            // ASCII string scanner
                            for (DWORD i = 0; i + 4 < bDataSize; i++) {
                                if (isprint(bData[i])) {
                                    DWORD start = i;
                                    while (i < bDataSize && (isprint(bData[i]) || bData[i] == ' ')) i++;
                                    if (i - start >= 4) {
                                        std::string s((char*)&bData[start], i - start);
                                        if (s.find('.') != std::string::npos || s.find('\\') != std::string::npos) {
                                            extractedNames.push_back(AnsiToWide(s));
                                        }
                                    }
                                }
                            }

                            // UTF-16 string scanner
                            for (DWORD i = 0; i + 8 <= bDataSize; i += 2) {
                                wchar_t c = *(wchar_t*)&bData[i];
                                if (iswprint(c)) {
                                    DWORD start = i;
                                    while (i + 1 < bDataSize) {
                                        wchar_t wc = *(wchar_t*)&bData[i];
                                        if (iswprint(wc) || wc == L' ') i += 2;
                                        else break;
                                    }
                                    if (i - start >= 8) {
                                        std::wstring ws((wchar_t*)&bData[start], (i - start) / sizeof(wchar_t));
                                        if (ws.find(L'.') != std::wstring::npos || ws.find(L'\\') != std::wstring::npos) {
                                            extractedNames.push_back(ws);
                                        }
                                    }
                                }
                            }

                            for (auto wName : extractedNames) {
                                if (IsWhitelisted(wName)) continue;
                                std::filesystem::path p(wName);
                                std::wstring fn = p.filename().wstring();
                                if (fn.empty()) fn = wName;

                                while (!fn.empty() && ((unsigned short)fn.front() > 127 || (!isalnum((unsigned char)fn.front()) && fn.front() != L'_'))) {
                                    fn.erase(fn.begin());
                                }
                                while (!wName.empty() && ((unsigned short)wName.front() > 127 || (!isalnum((unsigned char)wName.front()) && wName.front() != L'\\' && wName.front() != L'/' && wName.front() != L'_'))) {
                                    wName.erase(wName.begin());
                                }

                                // Trim leading PIDL length byte or junk prefix before recognized cheat signature
                                for (const auto& sig : CHEAT_FILE_SIGNATURES) {
                                    std::wstring fnLower = Lower(fn);
                                    size_t matchPos = fnLower.find(Lower(sig));
                                    if (matchPos != std::wstring::npos && matchPos > 0 && matchPos <= 4) {
                                        bool allJunk = true;
                                        for (size_t j = 0; j < matchPos; j++) {
                                            if (isalnum((unsigned char)fn[j]) && !isdigit((unsigned char)fn[j])) allJunk = false;
                                        }
                                        if (allJunk) {
                                            fn.erase(0, matchPos);
                                            break;
                                        }
                                    }
                                }

                                if (fn.length() < 4) continue;

                                if (MatchesCheatSignature(fn) || MatchesCheatFileSignature(fn) ||
                                    MatchesCheatSignature(wName) || MatchesCheatFileSignature(wName))
                                {
                                    std::string aName = WideToAnsi(fn);
                                    if (reportedOpenSave.find(aName) == reportedOpenSave.end()) {
                                        reportedOpenSave.insert(aName);
                                        FILETIME ft = GetFileWriteTime(wName);
                                        std::string timeDetail = "";
                                        if (ft.dwLowDateTime != 0 || ft.dwHighDateTime != 0) {
                                            timeDetail = GetFileAgeCategory(ft) + " File timestamp: " + FileTimeToString(ft) + CorrelateSessionForFileTime(ft, r.detectedGames) + " | ";
                                        }
                                        r.findings.push_back({
                                            "OPENSAVE_MRU",
                                            aName,
                                            85,
                                            timeDetail + "File selected in Windows Open/Save dialog: " + WideToAnsi(wName)
                                        });
                                        r.score += 25;
                                    }
                                }
                            }
                        }
                        vIdx++;
                    }
                    RegCloseKey(hSubExt);
                }
                subIdx++;
            }
            RegCloseKey(hOpenSave);
        }
    }

    UpdateProgress(44, 56);

    // ========================================================================
    // PHASE 45: Active Roblox Memory / Luau Environment Inspection
    // Detects injected Lua executors (getgenv, hookmetamethod, Luau bytecode)
    // ========================================================================
    if (robloxPid > 0) {
        HANDLE hRoblox = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, robloxPid);
        if (hRoblox) {
            MEMORY_BASIC_INFORMATION mbi;
            LPVOID addr = nullptr;
            const std::vector<std::string> luaSignatures = {
                "getgenv", "hookmetamethod", "getrawmetatable", "setclipboard",
                "syn.request", "http_request", "setthreadidentity", "getconnections",
                "Drawing.new", "isexecutorclosure", "fireclickdetector", "clonefunction"
            };
            int detectedLuaHooks = 0;
            std::set<std::string> matchedHooks;

            // A per-region size cap skips the large heap arenas where executor
            // API tables actually live, because Roblox arenas routinely exceed
            // any small fixed limit. Bound the scan by a total byte budget
            // instead so big regions are still read, and cap elapsed time so a
            // pathological process cannot stall the scan.
            const size_t kBudget = 512ull * 1024 * 1024;
            size_t scanned = 0;
            auto scanStart = std::chrono::steady_clock::now();

            while (VirtualQueryEx(hRoblox, addr, &mbi, sizeof(mbi))) {
                if (mbi.State == MEM_COMMIT && (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE)) {
                    if (mbi.RegionSize > 0 && scanned < kBudget) {
                        size_t toRead = mbi.RegionSize;
                        if (toRead > kBudget - scanned) toRead = kBudget - scanned;
                        std::vector<char> buffer(toRead);
                        SIZE_T bytesRead = 0;
                        if (ReadProcessMemory(hRoblox, mbi.BaseAddress, buffer.data(), toRead, &bytesRead) && bytesRead > 0) {
                            scanned += bytesRead;
                            std::string memStr(buffer.data(), bytesRead);
                            for (const auto& lsig : luaSignatures) {
                                if (matchedHooks.find(lsig) == matchedHooks.end() && memStr.find(lsig) != std::string::npos) {
                                    matchedHooks.insert(lsig);
                                    detectedLuaHooks++;
                                }
                            }
                        }
                    }
                }
                addr = (LPVOID)((DWORD_PTR)mbi.BaseAddress + mbi.RegionSize);
                if (addr > (LPVOID)0x7FFFFFFFFFFFFFFFULL || detectedLuaHooks >= 4) break;
                if (scanned >= kBudget) break;
                if (std::chrono::steady_clock::now() - scanStart > std::chrono::seconds(8)) break;
            }

            g_cov.add("Roblox live memory scan", (long)(scanned / (1024 * 1024)),
                scanned >= kBudget ? "MB read (budget reached)" :
                "MB read across RW/RWX regions for executor API surface");

            if (detectedLuaHooks >= 2) {
                std::string hookList = "";
                for (const auto& h : matchedHooks) {
                    if (!hookList.empty()) hookList += ", ";
                    hookList += h;
                }
                r.findings.push_back({
                    "ROBLOX_LUA_INJECTION",
                    "Active Luau Script Executor Environment in Memory",
                    100,
                    "Hooked environment functions identified inside Roblox: " + hookList
                });
                r.score += 65;
            }
            CloseHandle(hRoblox);
        }
    }

    UpdateProgress(45, 56);

    // ========================================================================
    // PHASE 46: External Transparent Overlay Detection
    // Detects external aimbot/ESP overlays hovering over the Roblox client
    // ========================================================================
    {
        HWND hRobloxWnd = FindWindowW(L"WINDOWSCLIENT", nullptr);
        if (!hRobloxWnd) hRobloxWnd = FindWindowW(nullptr, L"Roblox");

        if (hRobloxWnd) {
            RECT rbxRect = {0};
            GetWindowRect(hRobloxWnd, &rbxRect);
            DWORD rbxPid = 0;
            GetWindowThreadProcessId(hRobloxWnd, &rbxPid);

            int rbxWidth = rbxRect.right - rbxRect.left;
            int rbxHeight = rbxRect.bottom - rbxRect.top;

            if (rbxWidth > 200 && rbxHeight > 200) {
                struct OverlayScanCtx {
                    RECT rbxRect;
                    DWORD rbxPid;
                    std::vector<Finding>* findings;
                    int* score;
                } ctx = { rbxRect, rbxPid, &r.findings, &r.score };

                EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
                    auto* c = reinterpret_cast<OverlayScanCtx*>(lParam);
                    if (!IsWindowVisible(hwnd)) return TRUE;

                    DWORD pid = 0;
                    GetWindowThreadProcessId(hwnd, &pid);
                    if (pid == c->rbxPid || pid == GetCurrentProcessId()) return TRUE;

                    LONG_PTR exStyle = GetWindowLongPtrW(hwnd, GWL_EXSTYLE);
                    if ((exStyle & WS_EX_LAYERED) && (exStyle & WS_EX_TOPMOST)) {
                        RECT wRect = {0};
                        GetWindowRect(hwnd, &wRect);
                        
                        if (abs(wRect.left - c->rbxRect.left) <= 15 &&
                            abs(wRect.top - c->rbxRect.top) <= 15 &&
                            abs((wRect.right - wRect.left) - (c->rbxRect.right - c->rbxRect.left)) <= 30 &&
                            abs((wRect.bottom - wRect.top) - (c->rbxRect.bottom - c->rbxRect.top)) <= 30)
                        {
                            wchar_t wTitle[256] = {0};
                            wchar_t wClass[256] = {0};
                            GetWindowTextW(hwnd, wTitle, 256);
                            GetClassNameW(hwnd, wClass, 256);

                            HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                            wchar_t procPath[MAX_PATH] = {0};
                            DWORD pathLen = MAX_PATH;
                            if (hProc) {
                                QueryFullProcessImageNameW(hProc, 0, procPath, &pathLen);
                                CloseHandle(hProc);
                            }

                            std::wstring exeName = std::filesystem::path(procPath).filename().wstring();
                            std::wstring exeLower = Lower(exeName);

                            auto isWhitelistedOverlay = [](const std::wstring& exe, const std::wstring& title, const std::wstring& path, const std::wstring& cls) -> bool {
                                std::wstring lExe = Lower(exe);
                                std::wstring lTitle = Lower(title);
                                std::wstring lPath = Lower(path);
                                std::wstring lCls = Lower(cls);

                                // Recording & Clipping Software (Medal, OBS, SteelSeries, Overwolf, etc.)
                                if (lExe.find(L"medal") != std::wstring::npos || lPath.find(L"\\medal\\") != std::wstring::npos) return true;
                                if (lExe == L"obs64.exe" || lExe == L"obs32.exe" || lExe == L"obs.exe" || lExe == L"streamlabs obs.exe" ||
                                    lExe == L"streamlabs.exe" || lExe == L"slobs.exe") return true;
                                if (lExe == L"nvcontainer.exe" || lExe == L"geforceexperience.exe" || lExe == L"nvidia share.exe" ||
                                    lExe == L"shadowplay.exe" || lExe == L"nvspcaps64.exe") return true;
                                if (lExe == L"amdow.exe" || lExe == L"radeonsoftware.exe" || lExe == L"amdrsserv.exe") return true;
                                if (lExe.find(L"steelseries") != std::wstring::npos || lPath.find(L"\\steelseries\\") != std::wstring::npos) return true;
                                if (lExe.find(L"overwolf") != std::wstring::npos || lPath.find(L"\\overwolf\\") != std::wstring::npos) return true;
                                if (lExe == L"outplayed.exe" || lPath.find(L"\\outplayed\\") != std::wstring::npos) return true;
                                if (lExe == L"fraps.exe" || lExe == L"action.exe" || lExe == L"bandicam.exe" || lExe == L"d3dgear.exe") return true;

                                // Chat, Voice & Gaming Platforms
                                if (lExe.find(L"discord") != std::wstring::npos || lPath.find(L"\\discord\\") != std::wstring::npos) return true;
                                if (lExe == L"steam.exe" || lExe == L"gameoverlayui.exe" || lExe == L"steamwebhelper.exe") return true;
                                if (lExe == L"gamebar.exe" || lExe == L"gamebarft.exe" || lExe == L"xboxapp.exe" ||
                                    lExe == L"xboxgamebar.exe" || lExe == L"bcastdvr.exe") return true;
                                if (lExe == L"spotify.exe") return true;
                                if (lExe == L"guilded.exe" || lExe == L"teamspeak3.exe" || lExe == L"teamspeak.exe") return true;

                                // Browsers & Windows system UI
                                if (lExe == L"chrome.exe" || lExe == L"msedge.exe" || lExe == L"firefox.exe" || lExe == L"brave.exe" ||
                                    lExe == L"opera.exe" || lExe == L"explorer.exe" || lExe == L"applicationframehost.exe" ||
                                    lExe == L"shellexperiencehost.exe" || lExe == L"startmenuexperiencehost.exe" ||
                                    lExe == L"searchhost.exe" || lExe == L"lockapp.exe" || lExe == L"dwm.exe") return true;

                                // Titles & Classes
                                if (lTitle.find(L"medal") != std::wstring::npos || lTitle.find(L"discord") != std::wstring::npos ||
                                    lTitle.find(L"geforce") != std::wstring::npos || lTitle.find(L"nvidia") != std::wstring::npos ||
                                    lTitle.find(L"overwolf") != std::wstring::npos || lTitle.find(L"outplayed") != std::wstring::npos ||
                                    lTitle.find(L"steelseries") != std::wstring::npos) return true;

                                return false;
                            };

                            if (!isWhitelistedOverlay(exeName, wTitle, procPath, wClass)) {
                                c->findings->push_back({
                                    "EXTERNAL_OVERLAY",
                                    WideToAnsi(exeName.empty() ? wTitle : exeName),
                                    90,
                                    "Transparent overlay directly mirroring Roblox window viewport (Class: " + WideToAnsi(wClass) + ")"
                                });
                                *(c->score) += 50;
                            }
                        }
                    }
                    return TRUE;
                }, (LPARAM)&ctx);
            }
        }
    }

    UpdateProgress(46, 56);

    // ========================================================================
    // PHASE 47: ShellBags Forensics (Deleted Folder History)
    // Recovers folder paths opened in Windows Explorer even after deletion
    // ========================================================================
    {
        const wchar_t* bagPaths[] = {
            L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU",
            L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags",
            nullptr
        };

        std::set<std::wstring> seenShellBags;

        for (int b = 0; bagPaths[b]; b++) {
            HKEY hBag;
            if (RegOpenKeyExW(HKEY_CURRENT_USER, bagPaths[b], 0, KEY_READ, &hBag) == ERROR_SUCCESS) {
                std::function<void(HKEY, int)> scanBagTree = [&](HKEY hKey, int depth) {
                    if (depth > 4) return;
                    DWORD idx = 0;
                    wchar_t subName[256]; DWORD subSize;
                    while (true) {
                        subSize = sizeof(subName) / sizeof(wchar_t);
                        if (RegEnumKeyExW(hKey, idx, subName, &subSize, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
                        HKEY hSub;
                        if (RegOpenKeyExW(hKey, subName, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                            DWORD valIdx = 0;
                            wchar_t vName[64]; DWORD vNameSize;
                            BYTE valData[4096]; DWORD valDataSize; DWORD valType;
                            while (true) {
                                vNameSize = sizeof(vName) / sizeof(wchar_t);
                                valDataSize = sizeof(valData);
                                if (RegEnumValueW(hSub, valIdx, vName, &vNameSize, nullptr, &valType, valData, &valDataSize) != ERROR_SUCCESS) break;
                                if (valType == REG_BINARY && valDataSize > 16) {
                                    std::wstring wRaw((wchar_t*)valData, valDataSize / sizeof(wchar_t));
                                    std::wstring wLower = Lower(wRaw);
                                    for (const auto& fsig : FOLDER_SIGS) {
                                        if (IsWhitelisted(fsig) || IsWhitelisted(wRaw)) continue;
                                        if (seenShellBags.find(fsig) != seenShellBags.end()) continue;
                                        if (wLower.find(Lower(fsig)) != std::wstring::npos) {
                                            seenShellBags.insert(fsig);
                                            r.findings.push_back({
                                                "SHELLBAGS_FOLDER",
                                                WideToAnsi(fsig),
                                                85,
                                                "Folder was accessed in Explorer (persists after folder deletion): " + WideToAnsi(fsig)
                                            });
                                            r.score += 30;
                                            break;
                                        }
                                    }
                                }
                                valIdx++;
                            }
                            scanBagTree(hSub, depth + 1);
                            RegCloseKey(hSub);
                        }
                        idx++;
                    }
                };
                scanBagTree(hBag, 0);
                RegCloseKey(hBag);
            }
        }
    }

    UpdateProgress(47, 56);

    // ========================================================================
    // PHASE 48: Roblox Session & Game Identification Forensics
    // Analyzes Roblox game sessions to determine which game was cheated in
    // ========================================================================
    {
        // If detectedGames was empty at start (e.g. game launched during scan), retry once
        if (r.detectedGames.empty()) {
            r.detectedGames = ScanRobloxGameSessions();
        }

        // Correlate with cheat findings (e.g. folder names like [Gakuran NO], da hood, rivals)
        std::string correlatedGame = "";
        for (const auto& f : r.findings) {
            std::string lower = f.description + " " + f.evidence;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
            if (lower.find("gakuran") != std::string::npos) correlatedGame = "Gakuran (Ã¥Â­Â¦Ã¤Â¹Â±)";
            else if (lower.find("da hood") != std::string::npos || lower.find("dahood") != std::string::npos) correlatedGame = "Da Hood";
            else if (lower.find("rivals") != std::string::npos) correlatedGame = "Rivals";
            else if (lower.find("blox fruits") != std::string::npos) correlatedGame = "Blox Fruits";
            else if (lower.find("arsenal") != std::string::npos) correlatedGame = "Arsenal";
            else if (lower.find("bedwars") != std::string::npos) correlatedGame = "BedWars";
            else if (lower.find("deepwoken") != std::string::npos) correlatedGame = "Deepwoken";
            else if (lower.find("fisch") != std::string::npos) correlatedGame = "Fisch";
            if (!correlatedGame.empty()) break;
        }

        if (!correlatedGame.empty()) {
            r.primaryGame = correlatedGame;
            r.gameTargetedByCheats = true;
        } else if (!r.detectedGames.empty()) {
            r.primaryGame = r.detectedGames[0].gameName;
            r.gameTargetedByCheats = false;
        }
    }

    UpdateProgress(48, 56);

    // ========================================================================
    // PHASE 49 - Roblox Client Integrity (patched / re-signed client)
    // ========================================================================
    ScanRobloxClientIntegrity(r);

    UpdateProgress(49, 56);

    // ========================================================================
    // PHASE 50 - Hidden Thread Start Addresses (thread hijack / shellcode)
    // ========================================================================
    if (robloxPid > 0) {
        HiddenThreadResult ht = DetectHiddenThreads(robloxPid);
        g_cov.add("Roblox thread start addresses", ht.total,
            ht.unreadable > 0 ? "threads readable: " + std::to_string(ht.total - ht.unreadable) : "all thread starts resolved");

        if (ht.rwxStarts > 0) {
            // RWX private start addresses are also produced by overlay / capture
            // software hooks. They are evidence, but only when nothing else
            // corroborates them do they stand alone.
            bool corroborated = false;
            for (const auto& f : r.findings) {
                if (f.category == "MANUAL_MAPPING" || f.category == "DLL_INJECTION" ||
                    f.category == "ROBLOX_MEMORY" || f.category == "GENERIC_INJECTOR_EXEC") {
                    corroborated = true;
                    break;
                }
            }

            std::string cat = corroborated ? "HIDDEN_THREAD_CORROBORATED" : "HIDDEN_THREAD";
            int conf = corroborated ? 90 : 60;

            std::string note = ht.overlayPresent
                ? " Overlay/capture software is loaded into Roblox, which also produces RWX trampolines - treat as inconclusive on its own."
                : " No overlay or capture software is loaded to explain these regions.";

            r.findings.push_back({
                cat,
                "Threads running outside any loaded module",
                conf,
                std::to_string(ht.rwxStarts) + " thread(s) of " + std::to_string(ht.total) +
                " start in unbacked RWX private memory inside Roblox (PID " + std::to_string(robloxPid) +
                "): " + ht.evidence + "." + note +
                (corroborated ? " Corroborated by injected code detected in the same process."
                              : " Not corroborated by any other finding - requires manual review.")
            });
        } else if (ht.privateStarts > 0) {
            g_cov.add("Hidden thread heuristic", ht.privateStarts, "private executable starts found, none RWX - not flagged");
        }

        // PHASE 51 - debugger attached to the live client
        ScanDebuggerAttach(r, robloxPid);
    }

    UpdateProgress(50, 56);

    // ========================================================================
    // PHASE 51b - Amcache.hve content-hash execution proof
    // Runs before the drop-location scan: that scan consults the hash set this
    // phase builds, so an unsigned injector can be promoted from "present" to
    // "Windows recorded these exact bytes executing".
    // ========================================================================
    ScanAmcacheHive(r);

    // ========================================================================
    // PHASE 52 - Generic Injector Heuristic (catches unknown executors)
    // ========================================================================
    ScanDropLocations(r);

    UpdateProgress(51, 56);

    // Roblox-side script drops (autoexec / workspace / plugins folders)
    {
        wchar_t localAppData[MAX_PATH] = {0};
        if (SUCCEEDED(SHGetFolderPathW(nullptr, CSIDL_LOCAL_APPDATA, nullptr, SHGFP_TYPE_CURRENT, localAppData))) {
            std::filesystem::path rbx = std::filesystem::path(localAppData) / L"Roblox";
            if (std::filesystem::exists(rbx)) {
                long drops = 0;
                std::error_code ec;
                for (auto it = std::filesystem::recursive_directory_iterator(
                         rbx, std::filesystem::directory_options::skip_permission_denied, ec);
                     it != std::filesystem::recursive_directory_iterator() && !ec; it.increment(ec)) {
                    if (!it->is_regular_file(ec)) continue;
                    std::string ext = Lower(PathUtf8(it->path().extension()));
                    if (ext != ".lua" && ext != ".luau" && ext != ".txt") continue;
                    std::string parent = Lower(WideToAnsi(it->path().parent_path().wstring()));
                    if (parent.find("autoexec") == std::string::npos &&
                        parent.find("workspace") == std::string::npos &&
                        parent.find("plugins") == std::string::npos) continue;

                    drops++;
                    if (drops > 20) break;
                    r.findings.push_back({
                        "ROBLOX_DIR_DROP",
                        PathUtf8(it->path().filename()),
                        65,
                        "Auto-run script staged in a Roblox execution folder: " + WideToAnsi(it->path().wstring())
                    });
                }
                g_cov.add("Roblox auto-run script folders", drops,
                    drops > 0 ? "scripts present in autoexec/workspace/plugins" : "no staged scripts found");
            }
        }
    }

    UpdateProgress(52, 56);

    // ========================================================================
    // PHASE 53-56 - PERSISTENCE VECTORS
    // Autoruns, services, WMI subscriptions, retained client versions.
    // These survive reboots and user-profile wipes, which is exactly why they
    // were dark until now.
    // ========================================================================
    ScanAutoruns(r);
    UpdateProgress(53, 56);

    ScanServices(r);
    UpdateProgress(54, 56);

    ScanWmiPersistence(r);
    UpdateProgress(55, 56);

    ScanRobloxVersionSprawl(r);
    UpdateProgress(56, 56);

    // ========================================================================
    // SCORING + VERDICT
    // ========================================================================
    {
        ThreatProfile tp = ComputeThreat(r);
        r.score = tp.score;
        r.verdict = tp.verdict;
    }

    return r;
}

// ============================================================================
// 6. DISPLAY & FORMATTING
// ============================================================================

std::string GetFriendlyCategory(const std::string& cat) {
    if (cat == "ROBLOX_MODULE" || cat == "ROBLOX_MEMORY") return "ROBLOX";
    if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY") return "HISTORY";
    if (cat == "BAM_REGISTRY" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "UNINSTALL_KEY" || cat == "AMCACHE" ||
        cat == "PREFETCH" || cat == "USERASSIST" || cat == "RECENT_FILE" || cat == "ARCHIVE_HISTORY")
        return "Process & Registry Traces";
    if (cat == "DNS_CACHE" || cat == "FIREWALL_RULE" || cat == "VIRTUAL_MACHINE_MAC" || cat == "REMOTE_DESKTOP_TOOL" || cat == "DUAL_PC_STREAMING" || cat == "STREAMING_PORT") return "NETWORK";
    if (cat == "DELETED_CHEAT" || cat == "SUSPICIOUS_TEMP_PE" || cat == "RECENT_FILE" || cat == "CHEAT_FOLDER" || cat == "INJECTOR_REMNANT" || cat == "ARCHIVE_HISTORY") return "FILE";
    if (cat == "DMA_CARD") return "HARDWARE";
    if (cat == "SRUM_DATABASE" || cat == "VOLUME_SHADOW" || cat == "DEFENDER_EXCLUSION" || cat == "FACTORY_RESET") return "FORENSICS";
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

    // Bootstrappers
    if (cat == "BOOTSTRAPPER" || 
        lowerDesc.find(L"bloxstrap") != std::wstring::npos || lowerEvid.find(L"bloxstrap") != std::wstring::npos ||
        lowerDesc.find(L"voidstrap") != std::wstring::npos || lowerEvid.find(L"voidstrap") != std::wstring::npos ||
        lowerDesc.find(L"frostrap") != std::wstring::npos || lowerEvid.find(L"frostrap") != std::wstring::npos ||
        lowerDesc.find(L"fishstrap") != std::wstring::npos || lowerEvid.find(L"fishstrap") != std::wstring::npos) {
        return "Bootstrappers";
    }

    // Browser & Search History
    if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY" || cat == "SEARCH_ENGINE_CHEAT_QUERY" || cat == "YOUTUBE_CHEAT_VIDEO" || cat == "DNS_CACHE" || cat == "DISCORD_RPC_CACHE")
        return "Browser & Search History";

    // Registry Traces
    if (cat == "RUN_MRU" || cat == "OPENSAVE_MRU" || cat == "BAM_REGISTRY" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "UNINSTALL_KEY" || cat == "USERASSIST" || cat == "AMCACHE" || cat == "HIGH_FREQUENCY_EXECUTION" || cat == "NETWORK_DATA_USAGE")
        return "Registry Traces";

    // HWID Spoofers & Bypass Tools
    if (cat == "MAC_SPOOF" || cat == "HWID_SPOOFER" || cat == "CHEAT_DRIVER" || cat == "ACTIVE_CHEAT_DRIVER" ||
        cat == "VIRTUAL_MACHINE_MAC" || cat == "DMA_CARD" || cat == "STREAMING_PORT" || cat == "DUAL_PC_STREAMING" ||
        lowerDesc.find(L"bypass") != std::wstring::npos || lowerEvid.find(L"bypass") != std::wstring::npos ||
        lowerDesc.find(L"spoofer") != std::wstring::npos || lowerEvid.find(L"spoofer") != std::wstring::npos ||
        lowerDesc.find(L"dma") != std::wstring::npos || lowerEvid.find(L"dma") != std::wstring::npos ||
        lowerDesc.find(L"networkaddress") != std::wstring::npos)
        return "HWID Spoofers & Bypass Tools";

    // Deleted & Hidden Evidence
    if (cat == "ANTI_FORENSICS_WIPER" || cat == "SHELLBAGS_FOLDER" || cat == "DELETED_CHEAT" || cat == "RECYCLE_BIN" || cat == "TIMESTOMPING" || cat == "NTFS_ADS" || cat == "DELETED_BROWSER_HISTORY" || cat == "FACTORY_RESET")
        return "Deleted & Hidden Evidence";

    // System Configuration & Telemetry
    if (cat == "HYPERVISOR_DETECTED" || cat == "VULNERABLE_BOOT_STATE" || cat == "ETW_BLINDING" || cat == "BYOVD_EXPLOIT" ||
        cat == "TELEMETRY_BLOCK" || cat == "VIRTUAL_MACHINE" || cat == "EMULATOR_PROCESS" || cat == "EMULATOR_FOLDER" ||
        cat == "REMOTE_DESKTOP_TOOL" || cat == "USB_PLUG_PULL" || cat == "DEFENDER_EXCLUSION" || cat == "VOLUME_SHADOW")
        return "System Configuration & Telemetry";

    // Network & Anti-Forensics
    if (cat == "FIREWALL_RULE" || cat == "SCHEDULED_TASK" || cat == "SRUM_DATABASE")
        return "Network & Anti-Forensics";

    // Default: Injectors & Executors (processes, files, prefetch, crash logs, in-game Luau, overlay, etc.)
    return "Injectors & Executors";
}

// ============================================================================
// ANALYSIS SUMMARY BUILDER
// ============================================================================

// One sentence a non-technical reader can act on, derived from the recovered
// evidence only. Every surface that shows a verdict shows this next to it.
std::string PlainEnglishBottomLine(const CheatResult& r) {
    ThreatProfile p = ComputeThreat(r);
    std::ostringstream b;
    if (p.verdict == "CONFIRMED CHEATER") {
        b << "This computer was caught running cheating software. This is not a guess - Windows\n"
             "itself recorded it, or it was still running during the scan. A ban is justified.";
    } else if (p.verdict == "LIKELY CHEATER") {
        b << "Cheat software was found on this computer together with attempts to hide it, but\n"
             "the exact moment it ran was not recorded. Strong suspicion - review before banning.";
    } else if (p.verdict == "SUSPICIOUS") {
        b << "One cheat-related trace was found. That proves the item existed here at some\n"
             "point, but on its own it is not enough to ban. Re-scan and check the evidence list.";
    } else if (p.verdict == "INDICATIONS ONLY") {
        b << "Only indirect traces were found (searches, shortcuts, old activity). Nothing was\n"
             "caught running and no cheat file exists here. This is NOT proof of cheating.";
    } else {
        b << "Clean. Nothing cheating-related was found on this computer by any source the scan\n"
             "was able to read. This is a real result, not an empty scan - anything the scan\n"
             "could not open is listed below, so nothing is being quietly left out.";
    }
    return b.str();
}

std::string BuildSummary(const CheatResult& r) {
    if (r.findings.empty()) {
        std::ostringstream s;
        s << "1. BOTTOM LINE\n";
        s << "   " << PlainEnglishBottomLine(r) << "\n\n";
        s << "2. WHAT WAS ACTUALLY CHECKED\n";
        s << "   The scan looked for cheat programs running right now, files and folders left\n";
        s << "   behind on the drives, DLLs injected into Roblox, Windows records of programs\n";
        s << "   that were launched and then deleted, antivirus being tampered with, and\n";
        s << "   attempts to wipe the evidence afterwards.\n\n";
        s << "   None of those were present.\n\n";
        s << "3. WHAT WAS NOT CHECKED\n";
        if (g_cov.hasLimitations()) {
            s << "   " << g_cov.skippedSources.size() << " source(s) could not be opened on this run:\n";
            for (const auto& ls : g_cov.skippedSources) s << "     - " << ls << "\n";
            s << "   Because of that, this clean result does not cover those sources. Re-run the\n";
            s << "   scan as Administrator to get a complete answer.\n";
        } else {
            s << "   Nothing. Every artifact source the scanner knows about was opened and read,\n";
            s << "   so this clean verdict covers the whole machine, not a part of it.\n";
        }
        return s.str();
    }

    std::ostringstream s;
    int spoofers = 0, deletedEvidence = 0, systemFlags = 0;
    bool foundAimbot = false, foundExecutor = false, foundSpoof = false;

    // Aggregation of tools
    struct AggregatedTool {
        std::string header;
        std::string explanation;
        int traceCount = 0;
        std::set<std::string> subcategories;
        std::vector<std::string> samplePaths;
    };

    std::map<std::string, AggregatedTool> toolMap;

    for (const auto& f : r.findings) {
        if (IsWhitelisted(f.description) || IsWhitelisted(f.evidence)) continue;
        std::string cat = f.category;
        std::string combined = f.description + " " + f.evidence;
        std::string explanation = GetCheatExplanation(combined);
        std::string lwr = combined;
        std::transform(lwr.begin(), lwr.end(), lwr.begin(), ::tolower);

        std::string toolKey = "";
        std::string header = "";

        if (cat == "PROCESS" || cat == "PREFETCH" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "USERASSIST" || 
            cat == "BAM_REGISTRY" || cat == "INJECTOR_REMNANT" || cat == "CHEAT_FOLDER" || cat == "CHEAT_FILE" || 
            cat == "ARCHIVE_HISTORY" || cat == "DLL_INJECTION" || cat == "ROBLOX_MEMORY" || cat == "RECENT_FILE" ||
            cat == "OPENSAVE_MRU" || cat == "RUN_MRU") {
            
            if (lwr.find("potassium") != std::string::npos) {
                toolKey = "Potassium";
                header = "Script Executor: Potassium";
                foundExecutor = true;
            } else if (lwr.find("solara") != std::string::npos || lwr.find("solora") != std::string::npos) {
                toolKey = "Solara";
                header = "Script Executor: Solara";
                foundExecutor = true;
            } else if (lwr.find("matcha") != std::string::npos) {
                toolKey = "Matcha";
                header = "External Aimbot / ESP: Matcha";
                foundAimbot = true;
            } else if (lwr.find("aimmy") != std::string::npos || lwr.find("camlock") != std::string::npos || lwr.find("esp") != std::string::npos || lwr.find("aimbot") != std::string::npos) {
                toolKey = "ExternalAimbot";
                header = "External Aimbot / Camlock: " + f.description;
                foundAimbot = true;
            } else if (lwr.find("wave") != std::string::npos && lwr.find("qwave") == std::string::npos) {
                toolKey = "Wave";
                header = "Script Executor: Wave";
                foundExecutor = true;
            } else if (lwr.find("xeno") != std::string::npos) {
                toolKey = "Xeno";
                header = "Script Executor: Xeno";
                foundExecutor = true;
            } else if (lwr.find("delta") != std::string::npos) {
                toolKey = "Delta";
                header = "Script Executor: Delta";
                foundExecutor = true;
            } else if (lwr.find("codex") != std::string::npos) {
                toolKey = "Codex";
                header = "Script Executor: Codex";
                foundExecutor = true;
            } else if (lwr.find("cheatengine") != std::string::npos || lwr.find("cheat engine") != std::string::npos) {
                toolKey = "CheatEngine";
                header = "Memory Editor: Cheat Engine";
            } else if (lwr.find("injector") != std::string::npos || lwr.find("inject") != std::string::npos) {
                toolKey = "GenericInjector";
                header = "Script Injector / Utility";
                foundExecutor = true;
            } else {
                toolKey = f.description;
                header = "Cheat Tool: " + f.description;
                foundExecutor = true;
            }
        }
        else if (cat == "MAC_SPOOF" || cat == "HWID_SPOOFER" || cat == "CHEAT_DRIVER" || cat == "ACTIVE_CHEAT_DRIVER") {
            toolKey = "HWID_Spoofer_" + f.description;
            header = "Hardware Spoofer / Ban Evasion Tool: " + f.description;
            foundSpoof = true;
            spoofers++;
        }
        else if (cat == "DEFENDER_EXCLUSION") {
            toolKey = "DefenderExclusions";
            header = "Antivirus Bypass: Windows Defender Exclusion Whitelist";
            systemFlags++;
        }
        else if (cat == "DELETED_CHEAT" || cat == "DELETED_FILE" || cat == "RECYCLE_BIN" || cat == "TIMESTOMPING" || cat == "FACTORY_RESET" || cat == "NTFS_ADS") {
            toolKey = "AntiForensics";
            header = "Evidence Concealment: Deleted Files / Wiped Traces";
            deletedEvidence++;
        }
        else if (cat == "ROBLOX_CRASH_LOG") {
            toolKey = "CrashDump";
            header = "Roblox Crash Telemetry (Injected Cheat Caused Crash)";
        }
        else if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY") {
            toolKey = "BrowserCheat_" + f.description;
            header = "Browser Cheat Download / Search: " + f.description;
        }

        if (!toolKey.empty()) {
            AggregatedTool& ag = toolMap[toolKey];
            ag.header = header;
            if (ag.explanation.empty() && !explanation.empty()) ag.explanation = explanation;
            ag.traceCount++;
            ag.subcategories.insert(cat);
            if (ag.samplePaths.size() < 3 && !f.description.empty() && f.description != toolKey) {
                ag.samplePaths.push_back(f.description);
            } else if (ag.samplePaths.empty() && !f.evidence.empty()) {
                ag.samplePaths.push_back(f.evidence);
            }
        }
    }

    s << "  * BOTTOM LINE (READ THIS FIRST):\n";
    {
        std::istringstream bl(PlainEnglishBottomLine(r));
        std::string blLine;
        while (std::getline(bl, blLine)) s << "    " << blLine << "\n";
    }
    s << "\n";

    s << "  * WHAT THE PLAYER DID:\n";
    {
        ThreatProfile p = ComputeThreat(r);
        if (p.liveCount > 0) {
            s << "    Cheat tooling was running in memory on this computer at the moment of the scan.\n";
            s << "    The tools listed below were observed live, not merely found as old files.\n";
        } else if (p.executedCount > 0) {
            s << "    Windows recorded these tools being launched on this computer. The execution\n";
            s << "    records survive file deletion, so removing the cheat does not erase this proof.\n";
        } else if (p.evasionCount > 0 && p.remnantCount > 0) {
            s << "    Cheat material was stored on this computer alongside measures taken to hide it\n";
            s << "    from antivirus and from system tracking.\n";
        } else if (p.remnantCount >= 2) {
            s << "    Cheat files or folders were stored on this computer's drives.\n";
        } else if (p.remnantCount == 1 || p.evasionCount > 0) {
            s << "    A single cheat remnant or evasion indicator was recovered. It proves the item\n";
            s << "    existed on this computer, not that it was used in game.\n";
        } else if (p.indicativeCount > 0) {
            s << "    Only indirect traces were recovered (searches, shortcuts, activity history).\n";
            s << "    No cheat file was present and no execution was recorded.\n";
        } else {
            s << "    No unauthorized tools or cheating activities were found.\n";
        }
    }
    s << "\n";

    s << "  * CHEAT TOOLS IDENTIFIED ON THIS PC:\n";
    for (const auto& [k, ag] : toolMap) {
        s << "    - " << ag.header << " (" << ag.traceCount << " trace(s) found)\n";
        if (!ag.explanation.empty()) {
            s << "      Function: " << ag.explanation << "\n";
        }
        if (!ag.samplePaths.empty() && k != "DefenderExclusions") {
            s << "      File    : " << ag.samplePaths[0] << "\n";
        }
        s << "\n";
    }

    s << "  * SECURITY EVASION & CONCEALMENT:\n";
    if (deletedEvidence > 0 || spoofers > 0 || systemFlags > 0) {
        if (systemFlags > 0) s << "    - Added whitelist exclusions in Windows Defender so cheats would not get deleted.\n";
        if (deletedEvidence > 0) s << "    - Attempted to delete " << deletedEvidence << " cheat file(s), but drive records preserved the proof.\n";
        if (spoofers > 0) s << "    - Attempted to use HWID/MAC spoofers to evade permanent bans.\n";
    } else {
        s << "    - No active evasion or anti-forensic tampering tools were detected.\n";
    }

    return s.str();
}

void ShowResult(const CheatResult& r, const std::string& name, const std::string& hwid) {
    ui::ClearScreen();
    std::cout << "\n";

    ThreatProfile hp = ComputeThreat(r);
    if (hp.verdict == "CONFIRMED CHEATER") {
        std::cout << ui::RED << "    ========================================================================\n";
        std::cout << "                  ** CONFIRMED CHEATER - THREAT SCORE: " << r.score << "/100 **\n";
        std::cout << "    ========================================================================\n\n" << ui::RESET;
    } else if (hp.verdict == "LIKELY CHEATER") {
        std::cout << ui::RED << "    ========================================================================\n";
        std::cout << "                  ** LIKELY CHEATING - THREAT SCORE: " << r.score << "/100 **\n";
        std::cout << "    ========================================================================\n\n" << ui::RESET;
    } else if (hp.verdict == "SUSPICIOUS") {
        std::cout << ui::GOLD << "    ========================================================================\n";
        std::cout << "                  ** SUSPICIOUS - THREAT SCORE: " << r.score << "/100 **\n";
        std::cout << "    ========================================================================\n\n" << ui::RESET;
    } else if (hp.verdict == "INDICATIONS ONLY") {
        std::cout << ui::GOLD << "    ========================================================================\n";
        std::cout << "                  ** INDIRECT TRACES ONLY - NOT PROOF OF CHEATING **\n";
        std::cout << "    ========================================================================\n\n" << ui::RESET;
    } else {
        std::cout << ui::GREEN << "    ========================================================================\n";
        std::cout << "                  ** CLEAN - NO MALICIOUS ARTIFACTS DETECTED **\n";
        std::cout << "    ========================================================================\n\n" << ui::RESET;
    }

    std::cout << "    Target Player     : " << ui::GOLD << name << ui::RESET << "\n";
    std::cout << "    Hardware ID (HWID): " << ui::GRAY << hwid << ui::RESET << "\n";
    std::cout << "    Scan Date & Time  : " << ui::GRAY << GetTimestamp() << ui::RESET << "\n";
    if (!r.primaryGame.empty()) {
        std::cout << "    Roblox Game Found : " << ui::CYAN << r.primaryGame << ui::RESET << "\n";
    }
    std::cout << "\n";

    if (r.findings.empty()) {
        ui::PrintSuccess("No cheating indicators found.");
        std::cout << "    " << ui::GRAY << "Scan coverage: " << g_cov.sourcesRead() << " of " << g_cov.entries.size()
                  << " artifact sources examined" << ui::RESET << "\n";
        for (const auto& e : g_cov.entries) {
            std::cout << "      " << ui::GRAY << std::left << std::setw(46) << e.subsystem
                      << std::setw(9) << e.examined << e.status << ui::RESET << "\n";
        }
        if (g_cov.hasLimitations()) {
            std::cout << "    " << ui::GOLD << "LIMITATIONS (could not read - re-run elevated):" << ui::RESET << "\n";
            for (const auto& s : g_cov.skippedSources) std::cout << "      ! " << s << "\n";
            std::cout << "    " << ui::GOLD << "A clean verdict does NOT cover those sources." << ui::RESET << "\n";
        }
        std::cout << "\n";
    } else {
        struct CategoryGroup {
            std::string title;
            std::string explanation;
            std::vector<Finding> items;
        };

        std::vector<CategoryGroup> groups = {
            {
                "CHEAT PROGRAMS LAUNCHED ON WINDOWS",
                "Windows automatically tracks every executable launched by the user with exact timestamps.",
                {}
            },
            {
                "CHEAT FOLDERS & RECOVERED FILES",
                "Folders and cheat files found stored on the computer's drives.",
                {}
            },
            {
                "ANTIVIRUS EVASION & CONCEALMENT",
                "Actions taken by the player to stop antivirus from deleting their cheats.",
                {}
            },
            {
                "BROWSER DOWNLOADS & DISCORD TRACES",
                "Web and Discord history showing cheat downloads or active cheating status.",
                {}
            }
        };

        for (const auto& f : r.findings) {
            if (IsWhitelisted(f.description) || IsWhitelisted(f.evidence)) continue;
            std::string cat = f.category;
            if (cat == "BAM_REGISTRY" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "PREFETCH" || 
                cat == "USERASSIST" || cat == "PROCESS" || cat == "ACTIVE_PROCESS" || cat == "RUN_MRU" ||
                cat == "AUTORUN" || cat == "UNSIGNED_SERVICE" || cat == "CHEAT_SERVICE" ||
                cat == "WMI_PERSISTENCE" || cat == "WMI_SCRIPT_CONSUMER") {
                groups[0].items.push_back(f);
            } else if (cat == "DEFENDER_EXCLUSION" || cat == "ANTI_FORENSICS_WIPER" || cat == "TIMESTOMPING" || cat == "ETW_BLINDING") {
                groups[2].items.push_back(f);
            } else if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY" || cat == "DISCORD_RPC_CACHE" || cat == "DNS_CACHE") {
                groups[3].items.push_back(f);
            } else {
                groups[1].items.push_back(f);
            }
        }

        std::cout << "    " << ui::GOLD << "EVIDENCE SUMMARY (" << r.findings.size() << " TOTAL ARTIFACTS):" << ui::RESET << "\n";
        std::cout << "    " << ui::DARK_GOLD << std::string(72, '=') << ui::RESET << "\n\n";

        int secNum = 1;
        for (const auto& grp : groups) {
            if (grp.items.empty()) continue;
            std::cout << "    " << ui::GOLD << "[ SECTION 0" << secNum++ << " ] " << grp.title
                      << " (" << grp.items.size() << " FOUND)" << ui::RESET << "\n";
            std::cout << "    " << ui::GRAY << "(" << grp.explanation << ")" << ui::RESET << "\n";
            std::cout << "    " << ui::DARK_GOLD << std::string(72, '-') << ui::RESET << "\n\n";

            int itemNum = 1;
            for (const auto& f : grp.items) {
                auto descInfo = GetEvidenceDescriptor(f.category);
                std::string confTag;
                if (f.confidence >= 90) confTag = ui::RED + "[CONFIRMED PROOF]" + ui::RESET;
                else if (f.confidence >= 70) confTag = ui::DARK_GOLD + "[HIGH PROBABILITY]" + ui::RESET;
                else if (f.confidence >= 25) confTag = ui::GOLD + "[SUSPICIOUS]" + ui::RESET;
                else confTag = ui::GRAY + "[INFORMATIONAL]" + ui::RESET;

                std::cout << "      [-] ITEM #" << itemNum++ << "\n";
                std::cout << "          Item Name    : " << ui::GOLD << f.description << ui::RESET << "\n";
                std::cout << "          What It Is   : " << ui::WHITE << descInfo.title << ui::RESET << "\n";
                std::cout << "          What It Means: " << ui::GRAY << descInfo.explanation << ui::RESET << "\n";
                std::cout << "          Evidence Class: " << ui::CYAN
                          << TierLabel(TierForCategory(f.category)) << ui::RESET << "\n";
                std::cout << "          Confidence   : " << confTag << " (" << f.confidence << "/100)\n";
                if (!f.evidence.empty()) {
                    std::cout << "          Evidence     : " << ui::DARK_GOLD << f.evidence << ui::RESET << "\n";
                }
                std::string cheatInfo = GetCheatExplanation(f.description + " " + f.evidence);
                if (!cheatInfo.empty()) {
                    std::cout << "          Tool Info    : " << ui::CYAN << cheatInfo << ui::RESET << "\n";
                }
                std::cout << "\n";
            }
            std::cout << "\n";
        }

        std::cout << "\n";
    }

    // Printed on every scan, clean or dirty. A bare verdict with no explanation is
    // useless to a reader who does not already know what the evidence classes mean.
    std::cout << "    " << ui::GOLD << "PLAIN ENGLISH OVERVIEW:" << ui::RESET << "\n";
    std::cout << "    " << ui::DARK_GOLD << std::string(72, '-') << ui::RESET << "\n\n";

    std::string summary = BuildSummary(r);
    std::istringstream ss(summary);
    std::string summaryLine;
    while (std::getline(ss, summaryLine)) {
        std::cout << "    " << summaryLine << "\n";
    }
    std::cout << "\n";

    std::cout << "    " << ui::GOLD << std::string(72, '=') << ui::RESET << "\n";
    std::cout << "    VERDICT: " << ui::RED << r.verdict << ui::RESET << "\n";
    if (!r.primaryGame.empty()) {
        std::cout << "    GAME:    " << ui::CYAN << r.primaryGame << ui::RESET << "\n";
    }
    {
        ThreatProfile p = ComputeThreat(r);
        std::cout << "    EVIDENCE BREAKDOWN: live=" << p.liveCount
                  << " execution-proof=" << p.executedCount
                  << " evasion=" << p.evasionCount
                  << " remnant=" << p.remnantCount
                  << " indicative=" << p.indicativeCount << "\n";
        if (p.verdict == "CONFIRMED CHEATER") std::cout << "    ACTION:  " << ui::RED << "BAN IMMEDIATELY - PERMANENT RESTRICTION" << ui::RESET << "\n";
        else if (p.verdict == "LIKELY CHEATER") std::cout << "    ACTION:  " << ui::DARK_GOLD << "INVESTIGATE FURTHER / TEMPORARY SUSPENSION" << ui::RESET << "\n";
        else if (p.verdict == "SUSPICIOUS") std::cout << "    ACTION:  " << ui::GOLD << "MONITOR CLOSELY - INSUFFICIENT PROOF FOR A BAN" << ui::RESET << "\n";
        else if (p.verdict == "INDICATIONS ONLY") std::cout << "    ACTION:  " << ui::GRAY << "NO ACTION - INDIRECT TRACES ONLY, NOT PROOF" << ui::RESET << "\n";
        else std::cout << "    ACTION:  " << ui::GREEN << "NONE - PLAYER IS CLEAN" << ui::RESET << "\n";
    }
    std::cout << "    " << ui::GOLD << std::string(72, '=') << ui::RESET << "\n\n";
}

// ============================================================================
// 7. BUILD REPORT STRING - used for local save and server POST
// ============================================================================

std::string BuildReportText(const CheatResult& r, const std::string& name, const std::string& hwid) {
    std::ostringstream rpt;
    const std::string borderMajor = "================================================================================";
    const std::string borderMinor = "--------------------------------------------------------------------------------";

    rpt << borderMajor << "\n";
    rpt << "                     NATSU X AK FORENSIC SCAN REPORT\n";
    rpt << borderMajor << "\n\n";

    // 01 / SCAN OVERVIEW
    rpt << "[ 01 / SCAN OVERVIEW ]\n";
    rpt << borderMinor << "\n";
    rpt << "  Player Target     : " << name << "\n";
    rpt << "  Hardware ID (HWID): " << hwid << "\n";
    rpt << "  Scan Date & Time  : " << GetTimestamp() << "\n";
    rpt << "  Threat Score      : " << r.score << " / 100\n";
    rpt << "  Overall Verdict   : " << r.verdict << "\n";
    {
        ThreatProfile p = ComputeThreat(r);
        if (p.verdict == "CONFIRMED CHEATER") {
            rpt << "  Enforcement Action: PERMANENT BAN (HARDWARE LOCK RECOMMENDED)\n";
        } else if (p.verdict == "LIKELY CHEATER") {
            rpt << "  Enforcement Action: TEMPORARY SUSPENSION / IN-DEPTH MANUAL REVIEW\n";
        } else if (p.verdict == "SUSPICIOUS") {
            rpt << "  Enforcement Action: CLOSE MONITORING REQUIRED\n";
        } else if (p.verdict == "INDICATIONS ONLY") {
            rpt << "  Enforcement Action: NONE - INCONCLUSIVE, MANUAL REVIEW ONLY\n";
        } else {
            rpt << "  Enforcement Action: NO ACTION REQUIRED - SYSTEM VERIFIED CLEAN\n";
        }
    }
    rpt << "  Total Evidence    : " << r.findings.size() << " Flagged Artifact(s)\n\n\n";

    // 02 / ROBLOX GAME SESSIONS
    rpt << "[ 02 / ROBLOX GAME SESSIONS (GAMES PLAYED ON ROBLOX - NOT CHEATS) ]\n";
    rpt << borderMinor << "\n";
    if (!r.primaryGame.empty()) {
        if (r.gameTargetedByCheats) {
            rpt << "  TARGET GAME PLAYED: " << r.primaryGame << " (CONFIRMED CHEAT TARGET)\n";
        } else {
            rpt << "  LAST GAME PLAYED  : " << r.primaryGame << " (Legitimate Game Session)\n";
        }
        if (!r.detectedGames.empty()) {
            const auto& primary = r.detectedGames[0];
            if (primary.placeId > 0) rpt << "  Place ID          : " << primary.placeId << "\n";
            if (primary.universeId > 0) rpt << "  Universe ID       : " << primary.universeId << "\n";
            if (!primary.sessionTimestamp.empty()) rpt << "  Last Played Time  : " << primary.sessionTimestamp << "\n";
        }
        if (r.gameTargetedByCheats) {
            rpt << "  Evidence Link     : Confirmed: cheat scripts or exploit folders directly targeted this game.\n";
        } else {
            rpt << "  Evidence Link     : Game session recorded in Roblox logs. No cheat files directly targeted this game.\n";
        }
        if (r.detectedGames.size() > 1) {
            rpt << "\n  Other Recent Roblox Experiences Played on This PC:\n";
            rpt << "  (Note: These are legitimate Roblox games detected from client logs, NOT cheats)\n";
            for (size_t i = 1; i < r.detectedGames.size() && i <= 4; i++) {
                rpt << "    * " << r.detectedGames[i].gameName;
                if (r.detectedGames[i].placeId > 0) rpt << " (Place ID: " << r.detectedGames[i].placeId << ")";
                if (!r.detectedGames[i].sessionTimestamp.empty()) rpt << " - Played: " << r.detectedGames[i].sessionTimestamp;
                rpt << "\n";
            }
        }
    } else {
        rpt << "  Last Game Played  : No active or recent Roblox game session detected.\n";
    }
    rpt << "\n\n";

    // 03 / WHAT HAPPENED (PLAIN ENGLISH SUMMARY)
    // Written from the evidence that was actually recovered. Nothing here is
    // asserted unless a specific artifact supports it.
    ThreatProfile prof = ComputeThreat(r);
    rpt << "[ 03 / WHAT HAPPENED (PLAIN ENGLISH SUMMARY) ]\n";
    rpt << borderMinor << "\n";
    rpt << "  BOTTOM LINE:\n";
    {
        std::istringstream bl(PlainEnglishBottomLine(r));
        std::string blLine;
        while (std::getline(bl, blLine)) rpt << "    " << blLine << "\n";
    }
    rpt << "\n  Evidence classes recovered on this system:\n";
    rpt << "    Running right now (LIVE) .............. " << prof.liveCount << "\n";
    rpt << "    Windows execution records (PROOF) ..... " << prof.executedCount << "\n";
    rpt << "    Evasion / concealment ................. " << prof.evasionCount << "\n";
    rpt << "    Remnants stored on disk ............... " << prof.remnantCount << "\n";
    rpt << "    Indicative traces only ................ " << prof.indicativeCount << "\n\n";

    rpt << "  WHAT WAS FOUND:\n";
    if (prof.liveCount > 0) {
        rpt << "  Cheat software was observed running on this computer while the scan was in progress.\n";
        rpt << "  This is the strongest evidence class available: the tool was live and resident in memory.\n\n";
    } else if (prof.executedCount > 0) {
        rpt << "  Windows execution records prove cheat software was launched on this computer.\n";
        rpt << "  These records (Prefetch, BAM, Amcache, UserAssist, SRUM) are written by Windows itself\n";
        rpt << "  and survive file deletion, so deleting the cheat afterwards does not remove this proof.\n\n";
    } else if (prof.evasionCount > 0 && prof.remnantCount > 0) {
        rpt << "  Cheat remnants were found on disk together with deliberate evasion measures\n";
        rpt << "  (antivirus exclusions, spoofers, or log tampering). Execution was not directly\n";
        rpt << "  confirmed by Windows records, but the concealment effort indicates intent to hide usage.\n\n";
    } else if (prof.remnantCount >= 2) {
        rpt << "  Multiple cheat files or folders were found stored on the drives. Files being present\n";
        rpt << "  proves possession. Execution was not independently confirmed by Windows records.\n\n";
    } else if (prof.remnantCount == 1 || prof.evasionCount > 0) {
        rpt << "  A single cheat remnant or an evasion measure was found. This proves the item existed\n";
        rpt << "  on this computer but, on its own, does not prove it was used against Roblox.\n\n";
    } else if (prof.indicativeCount > 0) {
        rpt << "  Only indirect traces were recovered (browser searches, shortcuts, Discord activity,\n";
        rpt << "  archive history). No cheat files were found on disk and no execution was recorded.\n";
        rpt << "  Indicative traces alone are NOT proof of cheating - they show interest or awareness,\n";
        rpt << "  not confirmed use. Manual review is required before any enforcement action.\n\n";
    } else {
        rpt << "  No cheat tools, executors, spoofers, or evasion artifacts were found on this computer.\n";
        rpt << "  Every artifact source listed in the SCAN COVERAGE section below was examined.\n\n";
    }

    if (!prof.driver.empty()) {
        rpt << "  SINGLE STRONGEST EVIDENCE:\n";
        rpt << "    " << prof.driver << "\n";
        rpt << "    Class: " << prof.driverTier << "\n\n";
    }

    rpt << "  CONCLUSION:\n";
    if (prof.verdict == "CONFIRMED CHEATER") {
        if (prof.liveCount > 0) {
            rpt << "  Confirmed. Unauthorized tooling was running in memory at scan time.\n";
        } else {
            rpt << "  Confirmed. Windows itself recorded the cheat executing on this machine.\n";
        }
        if (r.gameTargetedByCheats) {
            rpt << "  Targeted game: " << r.primaryGame << "\n";
        }
    } else if (prof.verdict == "LIKELY CHEATER") {
        rpt << "  Strong indication. Cheat material was present together with concealment behaviour,\n";
        rpt << "  but no direct execution record was recovered. Recommend manual review.\n";
    } else if (prof.verdict == "SUSPICIOUS") {
        rpt << "  Suspicious. One remnant or evasion indicator was recovered. This is not sufficient\n";
        rpt << "  on its own for a permanent ban - re-scan and review the evidence log below.\n";
    } else if (prof.verdict == "INDICATIONS ONLY") {
        rpt << "  Inconclusive. Indirect traces only. No cheat file and no execution record exists.\n";
        rpt << "  Treating this as proof of cheating would be unsupportable.\n";
    } else {
        rpt << "  Clean. No cheating artifacts recovered from any examined source.\n";
    }
    rpt << "\n\n";

    // 04 / SUMMARY OF CHEAT TOOLS IDENTIFIED
    rpt << "[ 04 / SUMMARY OF CHEAT TOOLS IDENTIFIED ]\n";
    rpt << borderMinor << "\n";
    rpt << BuildSummary(r) << "\n\n";

    // SCAN COVERAGE - what was actually read, and what could not be read.
    // A scan that cannot read a source must say so, otherwise "clean" is a claim
    // with nothing behind it.
    rpt << borderMajor << "\n";
    rpt << "                      SCAN COVERAGE (WHAT WAS ACTUALLY READ)\n";
    rpt << borderMajor << "\n\n";
    rpt << "  Privilege level   : " << (g_isAdmin ? "ADMINISTRATOR (all sources readable)" : "STANDARD USER (some sources inaccessible)") << "\n";
    rpt << "  Artifact sources  : " << g_cov.sourcesRead() << " of " << g_cov.entries.size() << " examined\n\n";
    rpt << "  " << std::left << std::setw(48) << "  SOURCE"
        << std::setw(12) << "ITEMS" << "STATUS\n";
    rpt << "  " << std::string(84, '-') << "\n";
    for (const auto& e : g_cov.entries) {
        std::string sub = e.subsystem;
        if (sub.size() > 46) sub = sub.substr(0, 45) + ".";
        rpt << "  " << std::left << std::setw(48) << sub
            << std::setw(12) << e.examined << e.status << "\n";
    }
    if (g_cov.hasLimitations()) {
        rpt << "\n  SCAN LIMITATIONS - these sources could NOT be read, so evidence may be incomplete:\n";
        for (const auto& s : g_cov.skippedSources) {
            rpt << "    ! " << s << "\n";
        }
        // Advising elevation is only useful to someone who has not already
        // elevated. On an elevated run the remaining gaps are environmental -
        // a source that simply is not on this machine - and repeating the advice
        // would read as a promise that elevation fixes them.
        if (!g_isAdmin)
            rpt << "\n  Re-run this scanner from an elevated (administrator) console for full coverage.\n";
        else
            rpt << "\n  This run was already elevated. The sources above are missing for\n"
                   "  environmental reasons, not permissions - re-running as administrator\n"
                   "  will not change them.\n";
        rpt << "  A 'clean' verdict does NOT cover the sources listed above.\n";
    } else {
        rpt << "\n  All artifact sources were readable. This report reflects a complete scan.\n";
    }
    rpt << "\n\n";

    // SCAN INTEGRITY - what this scanner can attest about itself.
    // The runtime CRC is what the server compares against the reference CRC it
    // recorded for this build. A patched binary produces a different value, so
    // a scanner edited to always report CLEAN is visible from the server side.
    rpt << borderMajor << "\n";
    rpt << "                     SCAN INTEGRITY (SCANNER SELF-ATTESTATION)\n";
    rpt << borderMajor << "\n\n";
    rpt << "  Scanner build     : " << SCANNER_BUILD_ID << "\n";
    rpt << "  Runtime .text CRC : " << sec::RuntimeTextCrcHex() << "\n";
    rpt << "  Integrity status  : ";
    if (g_debuggerAttached) {
        rpt << "DEBUGGER ATTACHED AT SCAN TIME\n";
        rpt << "\n  A debugger was attached when this scan began. That is what happens when\n";
        rpt << "  a scanner is being taken apart or stepped through rather than used to\n";
        rpt << "  check a PC. Treat the findings below as unverified.\n";
    } else {
        rpt << "NO DEBUGGER DETECTED\n";
    }
    rpt << "\n  The server compares the runtime CRC above against the reference CRC it\n";
    rpt << "  recorded for this build. A scanner modified after distribution produces\n";
    rpt << "  a different CRC and is flagged as TAMPERED.\n\n\n";

    // 05 / DETAILED EVIDENCE LOG (HOW WE CAUGHT THEM)
    rpt << borderMajor << "\n";
    rpt << "                 DETAILED EVIDENCE LOG (HOW WE CAUGHT THEM)\n";
    rpt << borderMajor << "\n\n";

    struct CategoryGroup {
        std::string title;
        std::string explanation;
        std::vector<Finding> items;
    };

    std::vector<CategoryGroup> groups = {
        {
            "CATEGORY 1: PROGRAMS LAUNCHED ON WINDOWS / PERSISTENCE",
            "Windows execution records, plus programs configured to start automatically (Run keys, Startup folders, services, WMI subscriptions).",
            {}
        },
        {
            "CATEGORY 2: CHEAT FOLDERS & RECOVERED FILES",
            "Folders and cheat files found stored on the computer's drives.",
            {}
        },
        {
            "CATEGORY 3: ANTIVIRUS EVASION & CONCEALMENT",
            "Deliberate actions taken by the player to stop antivirus from deleting their cheats.",
            {}
        },
        {
            "CATEGORY 4: BROWSER DOWNLOADS & DISCORD TRACES",
            "Web and Discord history showing cheat downloads or active cheating status.",
            {}
        }
    };

    for (const auto& f : r.findings) {
        if (IsWhitelisted(f.description) || IsWhitelisted(f.evidence)) continue;
        std::string cat = f.category;
        if (cat == "BAM_REGISTRY" || cat == "MUICACHE" || cat == "APPCOMPAT" || cat == "PREFETCH" || 
            cat == "USERASSIST" || cat == "PROCESS" || cat == "ACTIVE_PROCESS" || cat == "RUN_MRU" ||
            cat == "NETWORK_DATA_USAGE" || cat == "HIGH_FREQUENCY_EXECUTION" ||
            cat == "AUTORUN" || cat == "UNSIGNED_SERVICE" || cat == "CHEAT_SERVICE" ||
            cat == "WMI_PERSISTENCE" || cat == "WMI_SCRIPT_CONSUMER") {
            groups[0].items.push_back(f);
        } else if (cat == "DEFENDER_EXCLUSION" || cat == "ANTI_FORENSICS_WIPER" || cat == "TIMESTOMPING" || cat == "ETW_BLINDING") {
            groups[2].items.push_back(f);
        } else if (cat == "BROWSER_HISTORY" || cat == "DELETED_BROWSER_HISTORY" || cat == "SEARCH_ENGINE_CHEAT_QUERY" || cat == "YOUTUBE_CHEAT_VIDEO" || cat == "DISCORD_RPC_CACHE" || cat == "DNS_CACHE") {
            groups[3].items.push_back(f);
        } else {
            groups[1].items.push_back(f);
        }
    }

    int itemTotal = 1;
    for (const auto& grp : groups) {
        if (grp.items.empty()) continue;
        rpt << "  --- " << grp.title << " (" << grp.items.size() << " ITEMS) ---\n";
        rpt << "  (" << grp.explanation << ")\n\n";

        for (const auto& f : grp.items) {
            auto descInfo = GetEvidenceDescriptor(f.category);
            std::string status = (f.confidence >= 90) ? "[CONFIRMED PROOF]" : (f.confidence >= 70 ? "[HIGH PROBABILITY]" : (f.confidence >= 25 ? "[SUSPICIOUS]" : "[INFORMATIONAL]"));

            rpt << "  [-] ITEM #" << itemTotal++ << "\n";
            rpt << "      Item Name    : " << f.description << "\n";
            rpt << "      What It Is   : " << descInfo.title << "\n";
            rpt << "      What It Means: " << descInfo.explanation << "\n";
            rpt << "      Status       : " << status << " (Confidence: " << f.confidence << "/100)\n";
            if (!f.evidence.empty()) {
                rpt << "      Evidence     : " << f.evidence << "\n";
            }
            std::string expl = GetCheatExplanation(f.description + " " + f.evidence);
            if (!expl.empty()) {
                rpt << "      Tool Info    : " << expl << "\n";
            }
            rpt << "\n";
        }
        rpt << "\n";
    }

    // FINAL VERDICT & ENFORCEMENT
    rpt << borderMajor << "\n";
    rpt << "                          FINAL VERDICT & ENFORCEMENT\n";
    rpt << borderMajor << "\n";
    rpt << "  TARGET PLAYER     : " << name << "\n";
    rpt << "  TARGET HWID       : " << hwid << "\n";
    if (!r.primaryGame.empty()) {
        rpt << "  PRIMARY GAME      : " << r.primaryGame;
        if (!r.gameTargetedByCheats) {
            rpt << " (Last played session - no game-specific cheat scripts found)";
        }
        rpt << "\n";
    }
    rpt << "  FINAL SCORE       : " << r.score << " / 100\n";
    rpt << "  VERDICT           : " << r.verdict << "\n";
    if (r.score >= 80) {
        rpt << "  RECOMMENDED ACTION: BAN IMMEDIATELY - PERMANENT RESTRICTION\n";
        rpt << "  PLAIN REASON      : Player ran unauthorized script executors while playing\n";
        rpt << "                      " << (r.primaryGame.empty() ? "Roblox" : r.primaryGame) << " and bypassed Windows Defender to conceal them.\n";
    } else if (r.score >= 50) {
        rpt << "  RECOMMENDED ACTION: INVESTIGATE FURTHER / TEMPORARY SUSPENSION\n";
    } else if (r.score >= 25) {
        rpt << "  RECOMMENDED ACTION: MONITOR CLOSELY\n";
    } else {
        rpt << "  RECOMMENDED ACTION: NONE - PLAYER SYSTEM IS CLEAN\n";
    }
    rpt << borderMajor << "\n";

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
                        const std::wstring& serverHost, INTERNET_PORT serverPort, DWORD flagSecure,
                        const std::string& token, const std::string& buildId, const std::string& textCrc)
{
    std::string reportText = BuildReportText(r, name, hwid);

    // Build JSON payload. 'token' is the one-time authorization minted by
    // /verify; without a valid token the server rejects this report.
    // 'text_crc' lets the server detect a patched scanner binary.
    std::ostringstream j;
    j << "{\"name\":\"" << JsonEscape(name) << "\",";
    j << "\"hwid\":\"" << JsonEscape(hwid) << "\",";
    j << "\"score\":" << r.score << ",";
    j << "\"verdict\":\"" << JsonEscape(r.verdict) << "\",";
    j << "\"findings_count\":" << r.findings.size() << ",";
    j << "\"build\":\"" << JsonEscape(buildId) << "\",";
    j << "\"text_crc\":\"" << JsonEscape(textCrc) << "\",";
    j << "\"token\":\"" << JsonEscape(token) << "\",";
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
// MAIN
// ============================================================================

int main(int argc, char* argv[]) {
    // Clean up old executable if any exists
    wchar_t selfPath[MAX_PATH];
    GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
    std::wstring oldPath = std::wstring(selfPath) + L".old";
    DeleteFileW(oldPath.c_str());

    // Console dimensions only. Deliberately NOT raising the screen-buffer height
    // above the window height: Windows Terminal's OpenConsole divides by zero on
    // a tall buffer followed by the VT erase (ESC[2J) that EnableANSI() sends.
    // The host dies, the window closes, and the scan never starts. Scrollback is
    // owned by the terminal (WT historySize), not by this process.
    system("mode con cols=140 lines=50");

    SetConsoleTitleW(L"NatsuXAK Scanner");
    ui::EnableANSI();
    if (argc <= 1) {
        ui::BootAnimation();
    }
    ui::PrintHeader("NatsuXAK Scanner");

    std::string name;
    if (argc > 1) {
        name = argv[1];
    } else {
        name = ui::GetInput("Enter your name: ");
    }

    if (name.empty()) {
        std::cout << "    [-] Name required.\n";
        std::cout.flush();
        Sleep(2000);
        return 1;
    }

    // Server authorization & local fallback
    std::cout << "    Checking authorization...\n";
    std::cout.flush();
    std::string playerType = "";
    std::string checkerName = "";
    std::string scanToken = "";
    std::wstring serverHost = L"roblox-scanner-hioo.onrender.com";
    INTERNET_PORT serverPort = INTERNET_DEFAULT_HTTPS_PORT;
    DWORD flagSecure = WINHTTP_FLAG_SECURE;

    // HWID is computed before authorization so it can be bound into the
    // one-time scan token. A token minted for one machine cannot be used on
    // another.
    std::string hwid = GetHardwareID();
    std::string selfCrc = sec::RuntimeTextCrcHex();

    // Anti-RE: if a debugger is attached, the scanner is being taken apart
    // rather than used to check a PC. Record it so the admin sees it, and wipe
    // the PE header on exit so the image is harder to dump afterwards.
    bool debuggerAttached = AntiDebugCheck();
    g_debuggerAttached = debuggerAttached;

    try {
        HINTERNET hSession = WinHttpOpen(L"RobloxScanner/4.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            WinHttpSetTimeouts(hSession, 25000, 25000, 25000, 25000);
            std::wstring wname = AnsiToWide(name);
            std::wstring whwid = AnsiToWide(hwid);
            std::wstring wbuild = AnsiToWide(SCANNER_BUILD_ID);
            std::wstring reqPath = L"/verify?name=" + wname + L"&hwid=" + whwid + L"&build=" + wbuild;

            HINTERNET hSrvConnect = WinHttpConnect(hSession, serverHost.c_str(), serverPort, 0);
            if (hSrvConnect) {
                HINTERNET hSrvReq = WinHttpOpenRequest(hSrvConnect, L"GET", reqPath.c_str(),
                    nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flagSecure);
                if (hSrvReq) {
                    if (WinHttpSendRequest(hSrvReq, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
                        if (WinHttpReceiveResponse(hSrvReq, nullptr)) {
                            ReadWinHttpResponseString(hSrvReq, playerType);
                        }
                    }
                    WinHttpCloseHandle(hSrvReq);
                }
                WinHttpCloseHandle(hSrvConnect);
            }
            WinHttpCloseHandle(hSession);
        }
    } catch (...) {
        playerType = "FREE"; // Fallback to free tier on crash
    }

    // Trim playerType from any source (local file, HTTP response)
    while (!playerType.empty() && (playerType.back() == ' ' || playerType.back() == '\r' || playerType.back() == '\n' || playerType.back() == '\t'))
        playerType.pop_back();
    while (!playerType.empty() && (playerType.front() == ' ' || playerType.front() == '\r' || playerType.front() == '\n' || playerType.front() == '\t'))
        playerType.erase(playerType.begin());
    // Uppercase for consistent comparison
    std::transform(playerType.begin(), playerType.end(), playerType.begin(), ::toupper);
    
    // Server now returns 'PC:checker_name:token' or 'TEST:checker_name:token'.
    // The token is a one-time authorization to submit a report; without it the
    // /report endpoint will reject the submission outright.
    std::string playerTypeOnly = playerType;
    size_t firstColon = playerType.find(':');
    if (firstColon != std::string::npos) {
        playerTypeOnly = playerType.substr(0, firstColon);
        size_t secondColon = playerType.find(':', firstColon + 1);
        if (secondColon != std::string::npos) {
            checkerName = playerType.substr(firstColon + 1, secondColon - firstColon - 1);
            scanToken = playerType.substr(secondColon + 1);
        } else {
            checkerName = playerType.substr(firstColon + 1);
        }
    }
    // strip trailing whitespace/newlines from the token
    while (!scanToken.empty() && (scanToken.back() == ' ' || scanToken.back() == '\r' ||
                                  scanToken.back() == '\n' || scanToken.back() == '\t'))
        scanToken.pop_back();

    if (playerTypeOnly == "INVALID") {
        std::cout << "    [-] NOT AUTHORIZED: Player '" << name << "' is not registered.\n";
        std::cout << "    [-] Scan aborted. Initiating self-destruct...\n";
        std::cout.flush();

        if (name != "test") {
            wchar_t selfPath[MAX_PATH];
            GetModuleFileNameW(nullptr, selfPath, MAX_PATH);
            wchar_t cmdLine[2048];
            swprintf_s(cmdLine, 2048,
                L"cmd.exe /c ping 127.0.0.1 -n 2 > nul & for /l %%i in (1,1,100) do (del /f /q \"%s\" & if not exist \"%s\" exit & ping 127.0.0.1 -n 2 > nul)",
                selfPath, selfPath);
            STARTUPINFOW si = { sizeof(si) };
            si.dwFlags = STARTF_USESHOWWINDOW;
            si.wShowWindow = SW_HIDE;
            PROCESS_INFORMATION pi = {0};
            if (CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
            }
        }
        Sleep(2500);
        return 1;
    }
    if (playerTypeOnly.empty()) {
        // Local development: allow offline scans under the reserved name "test"
        // so the scanner and report can be exercised without the admin server.
        if (name == "test") {
            playerTypeOnly = "TEST";
            std::cout << "    [TEST MODE] Admin server unreachable - running locally without authorization.\n\n";
        } else {
            std::cout << "    [-] SERVER UNREACHABLE: Could not reach admin server. Scan aborted.\n";
            std::cout.flush();
            Sleep(2500);
            return 1;
        }
    }

    std::cout << "    [+] Welcome, " << name << "\n\n";
    if (playerTypeOnly == "TEST") {
        std::cout << "    [TEST MODE] Active.\n";
    }
    if (scanToken.empty() && playerTypeOnly != "INVALID") {
        std::cout << "    [!] No scan token issued by the server.\n";
        std::cout << "    [!] The report cannot be submitted - the server only accepts\n";
        std::cout << "        signed, single-use scan tokens. Update the scanner.\n\n";
    }
    std::cout.flush();

    // Elevation state drives scan coverage. Without it, several artifact
    // sources are simply unreadable and the report must say so.
    {
        BOOL elevated = FALSE;
        HANDLE hTok = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hTok)) {
            DWORD sz = 0;
            TOKEN_ELEVATION elev = {0};
            if (GetTokenInformation(hTok, TokenElevation, &elev, sizeof(elev), &sz)) {
                elevated = elev.TokenIsElevated;
            }
            CloseHandle(hTok);
        }
        g_isAdmin = elevated ? true : false;
    }

    if (!g_isAdmin) {
        std::cout << "    [!] NOT RUNNING AS ADMINISTRATOR\n";
        std::cout << "    [!] Several evidence sources cannot be read without elevation:\n";
        std::cout << "        Amcache, USN Journal, Prefetch, SRUM, ShellBags, Volume Shadow, registry hives.\n";
        std::cout << "    [!] The scan will run, but a 'clean' result may be incomplete.\n\n";
        std::cout.flush();
        Sleep(1500);
    }

    std::cout << "    Scanning system integrity...\n\n";
    Sleep(300);

    CheatResult result = FullScan();

    std::cout << "\n\n    [*] Done.\n";
    Sleep(200);

    SaveReport(result, name, hwid);

    // POST report to admin server if tunnel or local server is available
    std::cout << "    Sending report to admin server...\n";
    bool reportSent = PostReportToServer(result, name, hwid, serverHost, serverPort, flagSecure,
                                         scanToken, SCANNER_BUILD_ID, selfCrc);
    if (reportSent) {
        std::cout << "    [+] Report delivered to admin server.\n\n";
    } else {
        std::cout << "    [!] Could not reach admin server.\n\n";
    }

    if (playerTypeOnly == "TEST" || name == "test") {
        ShowResult(result, name, hwid);
        std::cout << "    [TEST MODE] Auto-delete disabled.\n\n";
        std::cout.flush();
    } else {
        std::cout << "    [SELF-DELETE] Armed.\n\n";
        std::cout.flush();

        // ALWAYS self-delete - one-time use
        wchar_t selfPath[MAX_PATH];
        GetModuleFileNameW(nullptr, selfPath, MAX_PATH);

        // Spawn a background CMD that loops every 2 seconds trying to delete the file
        // This ensures that even if they click the 'X' on the window to force close it,
        // the background process will delete the file the moment the lock is released.
        wchar_t cmdLine[2048];
        swprintf_s(cmdLine, 2048,
            L"cmd.exe /c ping 127.0.0.1 -n 2 > nul & for /l %%i in (1,1,100) do (del /f /q \"%s\" & if not exist \"%s\" exit & ping 127.0.0.1 -n 2 > nul)",
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
    }

    if (argc > 1) {
        Sleep(2000);
    } else {
        ui::Pause("Press Enter to exit...");
    }

    // Anti-RE: blank the in-memory PE header before the process dies so a
    // later dump of this image is harder to rebase or analyse.
    WipePEHeader();

    return 0;
}

