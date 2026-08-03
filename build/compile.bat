@echo off
color 0A
echo.
echo    Building NatsuXAK Scanner v5.0...
echo.

if not exist "..\bin" mkdir "..\bin"
if not exist "..\pc_checker" mkdir "..\pc_checker"
if not exist "..\pc_checker\reports" mkdir "..\pc_checker\reports"

:: ============================================================
:: COMPILE RESOURCES (Icon)
:: ============================================================

echo    [*] Compiling resources...
windres ..\src\resource.rc -O coff -o ..\src\resource.res

:: ============================================================
:: BUILD ADMIN PANEL (admin.exe)
:: ============================================================

echo    [1/3] Building admin.exe...

where cl >nul 2>nul
if %errorlevel% equ 0 (
    rc /nologo ..\src\resource.rc
    cl /nologo /O2 /MT /EHsc /std:c++17 ..\src\admin.cpp ..\src\resource.res /link /out:"..\bin\admin.exe" winhttp.lib bcrypt.lib shell32.lib user32.lib /RELEASE
    goto check_admin
)

where g++ >nul 2>nul
if %errorlevel% equ 0 (
    g++ -std=c++17 -O2 -s -DNDEBUG -o "..\bin\admin.exe" ..\src\admin.cpp ..\src\resource.res -lwinhttp -lbcrypt -lshell32 -static -Wl,--dynamicbase,--nxcompat
    goto check_admin
)

:check_admin
if %errorlevel% neq 0 (
    echo.
    echo    [-] admin.exe build FAILED!
    echo.
    pause
    exit /b 1
)
echo    [+] admin.exe built.
echo.

:: ============================================================
:: BUILD SCANNER
:: ============================================================

echo    [2/3] Building scanner.exe...

:: Try MSVC first
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Using MSVC compiler
    rc /nologo ..\src\resource.rc
    cl /EHsc /std:c++17 /O2 /DNDEBUG /GS /DYNAMICBASE /NXCOMPAT /Fe:..\bin\scanner.exe ..\src\scanner.cpp ..\src\resource.res /link advapi32.lib winhttp.lib iphlpapi.lib crypt32.lib wintrust.lib ntdll.lib psapi.lib shell32.lib ole32.lib ws2_32.lib /RELEASE
    goto check_scanner
)

:: Fall back to MinGW/GCC
where g++ >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Using MinGW g++ compiler
    g++ -std=c++17 -O2 -s -DNDEBUG -o ..\bin\scanner.exe ..\src\scanner.cpp ..\src\resource.res -lwinhttp -liphlpapi -lcrypt32 -lwintrust -lntdll -lpsapi -lshell32 -lole32 -lws2_32 -static -Wl,--dynamicbase,--nxcompat
    goto check_scanner
)

echo    [-] No compiler found!
echo    Install Visual Studio Build Tools (cl.exe) or MinGW-w64 (g++.exe)
pause
exit /b 1

:check_scanner
if %errorlevel% neq 0 (
    echo.
    echo    [-] Scanner build FAILED!
    echo.
    pause
    exit /b 1
)
echo    [+] scanner.exe built.
echo.

:: ============================================================
:: BUILD CHECKER (NatsuXAK Service)
:: ============================================================

echo    [3/3] Building NatsuXAK Service.exe...

where cl >nul 2>nul
if %errorlevel% equ 0 (
    rc /nologo ..\src\resource.rc
    cl /nologo /O2 /MT /EHsc /std:c++17 ..\src\checker.cpp ..\src\resource.res /link /out:"..\bin\NatsuXAK Service.exe" winhttp.lib bcrypt.lib shell32.lib user32.lib /RELEASE
    goto check_checker
)

where g++ >nul 2>nul
if %errorlevel% equ 0 (
    g++ -std=c++17 -O2 -s -DNDEBUG -o "..\bin\NatsuXAK Service.exe" ..\src\checker.cpp ..\src\resource.res -lwinhttp -lbcrypt -lshell32 -static -Wl,--dynamicbase,--nxcompat
    goto check_checker
)

:check_checker
if %errorlevel% neq 0 (
    echo.
    echo    [-] NatsuXAK Service build FAILED!
    echo.
    pause
    exit /b 1
)
echo    [+] NatsuXAK Service.exe built.
echo.

:: ============================================================
:: UPX COMPRESSION (optional)
:: ============================================================

where upx >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Compressing with UPX...
    upx --best --lzma "..\bin\scanner.exe" >nul 2>nul
    upx --best --lzma "..\bin\NatsuXAK Service.exe" >nul 2>nul
    upx --best --lzma "..\bin\admin.exe" >nul 2>nul
    echo    [+] UPX compression applied.
    echo.
) else (
    echo    [*] UPX not found, skipping compression.
    echo.
)

:: ============================================================
:: COPY TO DISTRIBUTION FOLDER
:: ============================================================

echo    [*] Copying to pc_checker/ distribution folder...
copy /Y "..\bin\scanner.exe" "..\dist\Suspect\scanner.exe" >nul
copy /Y "..\bin\NatsuXAK Service.exe" "..\dist\PC_Checker\NatsuXAK Service.exe" >nul
copy /Y "..\bin\NatsuXAK Service.exe" "..\dist\Owner\NatsuXAK Service.exe" >nul
copy /Y "..\bin\admin.exe" "..\dist\Owner\admin.exe" >nul

echo    [+] Distribution folder ready.
echo.

:: ============================================================
:: CLEANUP MSVC BUILD ARTIFACTS
:: ============================================================

del /q ..\src\*.obj >nul 2>nul
del /q ..\bin\*.obj >nul 2>nul
del /q ..\bin\*.lib >nul 2>nul
del /q ..\bin\*.exp >nul 2>nul

:: ============================================================
:: DONE
:: ============================================================

echo    ========================================================
echo    BUILD COMPLETE - NatsuXAK Scanner
echo    ========================================================
echo.
echo    Outputs:
echo      ..\bin\scanner.exe
echo      ..\bin\NatsuXAK Service.exe
echo      ..\bin\admin.exe
echo.
echo    Distribution:
echo      ..\dist\Suspect\scanner.exe
echo      ..\dist\PC_Checker\NatsuXAK Service.exe
echo      ..\dist\Owner\admin.exe
echo      ..\dist\Owner\NatsuXAK Service.exe
echo.
pause
