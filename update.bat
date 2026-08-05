@echo off
title NatsuXAK Auto-Updater
color 0B

echo ========================================================
echo               NatsuXAK Auto-Updater
echo ========================================================
echo.
echo [*] Checking for updates from GitHub...

:: Define the raw GitHub URLs for the compiled binaries
set "URL_SCANNER=https://raw.githubusercontent.com/rahre/Roblox-Scanner/main/Owner/scanner.exe"
set "URL_SERVICE=https://raw.githubusercontent.com/rahre/Roblox-Scanner/main/Owner/service.exe"

:: Create a temporary folder for downloads
if not exist "temp_update" mkdir "temp_update"

echo [*] Downloading latest scanner.exe...
powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL_SCANNER%', 'temp_update\scanner.exe')"
if %errorlevel% neq 0 (
    echo [!] Failed to download scanner.exe. Check your internet connection.
    goto :cleanup
)

echo [*] Downloading latest service.exe...
powershell -Command "(New-Object Net.WebClient).DownloadFile('%URL_SERVICE%', 'temp_update\service.exe')"
if %errorlevel% neq 0 (
    echo [!] Failed to download service.exe.
    goto :cleanup
)

echo.
echo [+] Downloads complete. Installing updates...

:: Kill running instances if they exist so we can overwrite them
taskkill /F /IM scanner.exe 2>nul
taskkill /F /IM service.exe 2>nul

:: Give Windows a second to release the file locks
timeout /t 2 /nobreak >nul

:: Copy files from temp_update to the Owner folder (if it exists)
if exist "Owner" (
    echo [*] Updating Owner folder...
    copy /y "temp_update\scanner.exe" "Owner\scanner.exe" >nul
    copy /y "temp_update\service.exe" "Owner\service.exe" >nul
)

:: Copy files to the PC Check folder (if it exists)
if exist "PC Check" (
    echo [*] Updating PC Check folder...
    copy /y "temp_update\scanner.exe" "PC Check\scanner.exe" >nul
    copy /y "temp_update\service.exe" "PC Check\service.exe" >nul
)

:: Cleanup
:cleanup
echo [*] Cleaning up temporary files...
rd /s /q "temp_update"

echo.
echo ========================================================
echo                 UPDATE COMPLETE
echo ========================================================
echo [+] You are now running the latest version of NatsuXAK!
echo.
pause
