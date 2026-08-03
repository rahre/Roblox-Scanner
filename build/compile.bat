@echo off
color 0A
echo.
echo    Building Gakuran Cheater Checker v5.0...
echo.

if not exist "..\bin" mkdir "..\bin"
if not exist "..\pc_checker" mkdir "..\pc_checker"
if not exist "..\pc_checker\reports" mkdir "..\pc_checker\reports"

:: ============================================================
:: BUILD SCANNER
:: ============================================================

echo    [1/2] Building scanner.exe...

:: Try MSVC first
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Using MSVC compiler
    cl /EHsc /std:c++17 /O2 /DNDEBUG /GS /DYNAMICBASE /NXCOMPAT /Fe:..\bin\scanner.exe ..\src\scanner.cpp /link winhttp.lib iphlpapi.lib crypt32.lib wintrust.lib ntdll.lib psapi.lib shell32.lib ole32.lib ws2_32.lib /RELEASE
    goto check_scanner
)

:: Fall back to MinGW/GCC
where g++ >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Using MinGW g++ compiler
    g++ -std=c++17 -O2 -s -DNDEBUG -o ..\bin\scanner.exe ..\src\scanner.cpp -lwinhttp -liphlpapi -lcrypt32 -lwintrust -lntdll -lpsapi -lshell32 -lole32 -lws2_32 -static -Wl,--dynamicbase,--nxcompat
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
:: BUILD CHECKER (Gakuran Team)
:: ============================================================

echo    [2/2] Building Gakuran Team.exe...

where cl >nul 2>nul
if %errorlevel% equ 0 (
    cl /EHsc /std:c++17 /O2 /DNDEBUG /GS /DYNAMICBASE /NXCOMPAT /Fe:"..\bin\Gakuran Team.exe" ..\src\checker.cpp /link winhttp.lib bcrypt.lib shell32.lib /RELEASE
    goto check_checker
)

where g++ >nul 2>nul
if %errorlevel% equ 0 (
    g++ -std=c++17 -O2 -s -DNDEBUG -o "..\bin\Gakuran Team.exe" ..\src\checker.cpp -lwinhttp -lbcrypt -lshell32 -static -Wl,--dynamicbase,--nxcompat
    goto check_checker
)

:check_checker
if %errorlevel% neq 0 (
    echo.
    echo    [-] Gakuran Team build FAILED!
    echo.
    pause
    exit /b 1
)
echo    [+] Gakuran Team.exe built.
echo.

:: ============================================================
:: UPX COMPRESSION (optional)
:: ============================================================

where upx >nul 2>nul
if %errorlevel% equ 0 (
    echo    [*] Compressing with UPX...
    upx --best --lzma "..\bin\scanner.exe" >nul 2>nul
    upx --best --lzma "..\bin\Gakuran Team.exe" >nul 2>nul
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
copy /Y "..\bin\scanner.exe" "..\pc_checker\scanner.exe" >nul
copy /Y "..\bin\Gakuran Team.exe" "..\pc_checker\Gakuran Team.exe" >nul

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
echo    BUILD COMPLETE - Gakuran Cheater Checker v5.0
echo    ========================================================
echo.
echo    Outputs:
echo      ..\bin\scanner.exe
echo      ..\bin\Gakuran Team.exe
echo.
echo    Distribution:
echo      ..\pc_checker\scanner.exe
echo      ..\pc_checker\Gakuran Team.exe
echo.
pause
