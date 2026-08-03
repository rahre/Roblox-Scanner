@echo off
setlocal enabledelayedexpansion
title NatsuXAK Scanner - Admin Panel
color 06

set "RENDER_URL=https://roblox-scanner-hioo.onrender.com"

cls
echo.
echo 浜様様様様様様様様様様様様様様様様様様様様様様様様様様様融
echo 突     NatsuXAK Scanner - ADMIN PANEL         突
echo 突                  Made by AK and Natsu              突
echo 藩様様様様様様様様様様様様様様様様様様様様様様様様様様様夕
echo.
set /p ADMIN_NAME="    Enter Name: "
set /p ADMIN_KEY="    Enter Key: "

echo.
echo    Authenticating...

set ROLE=invalid
for /L %%a in (1,1,5) do (
    for /f "delims=" %%i in ('powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri ('%RENDER_URL%/auth?name=' + '%ADMIN_NAME%' + '&key=' + '%ADMIN_KEY%') -TimeoutSec 30; $r.role } catch { 'invalid' }" 2^>nul') do set ROLE=%%i
    if not "!ROLE!"=="invalid" goto auth_done
    echo    Retrying...
    timeout /t 3 >nul
)

:auth_done
if "!ROLE!"=="invalid" (
    echo.
    echo    [-] Access denied.
    pause
    exit
)

:menu
cls
echo.
echo 浜様様様様様様様様様様様様様様様様様様様様様様様様様様様融
echo 突     NatsuXAK Scanner - ADMIN PANEL         突
echo 突                  Made by AK and Natsu              突
echo 藩様様様様様様様様様様様様様様様様様様様様様様様様様様様夕
echo.

:: Check server health
for /f "delims=" %%i in ('powershell -NoProfile -Command "try { $r = Invoke-RestMethod -Uri '%RENDER_URL%/health' -TimeoutSec 5; 'ONLINE' } catch { 'OFFLINE' }" 2^>nul') do set STATUS=%%i
echo    Server: [%STATUS%]
echo    Logged in as: %ADMIN_NAME% (%ROLE%)
echo.

if "%ROLE%"=="master" (
    echo    [1] Add Player ^(one-time use^)
    echo    [2] View Reports
    echo    [3] Add Checker
    echo    [4] Remove Checker
    echo    [5] List Checkers
    echo    [6] Delete Report
    echo    [7] Server Status
    echo    [8] Exit
    echo.
    echo 陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳
    echo.
    set /p choice="Select (1-8): "

    if "!choice!"=="1" goto add_player
    if "!choice!"=="2" goto reports
    if "!choice!"=="3" goto add_checker
    if "!choice!"=="4" goto remove_checker
    if "!choice!"=="5" goto list_checkers
    if "!choice!"=="6" goto delete_report
    if "!choice!"=="7" goto server_status
    if "!choice!"=="8" goto exit
) else if "%ROLE%"=="owner" (
    echo    [1] Add Player ^(one-time use^)
    echo    [2] View Reports
    echo    [3] Add Checker
    echo    [4] Remove Checker
    echo    [5] List Checkers
    echo    [6] Exit
    echo.
    echo 陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳
    echo.
    set /p choice="Select (1-6): "

    if "!choice!"=="1" goto add_player
    if "!choice!"=="2" goto reports
    if "!choice!"=="3" goto add_checker
    if "!choice!"=="4" goto remove_checker
    if "!choice!"=="5" goto list_checkers
    if "!choice!"=="6" goto exit
) else (
    echo    [1] Add Player ^(one-time use^)
    echo    [2] View Reports
    echo    [3] Exit
    echo.
    echo 陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳陳
    echo.
    set /p choice="Select (1-3): "

    if "!choice!"=="1" goto add_player
    if "!choice!"=="2" goto reports
    if "!choice!"=="3" goto exit
)
goto menu

:add_player
cls
echo.
echo    ADD PLAYER
echo    One-time use -- scanner auto-deletes after scan.
echo.
set /p name="    Player name: "
if "%name%"=="" goto menu

powershell -NoProfile -Command "try { Invoke-RestMethod -Uri '%RENDER_URL%/player/add' -Method Post -Body ('{\"auth_name\":\"%ADMIN_NAME%\",\"auth_key\":\"%ADMIN_KEY%\",\"player_name\":\"%name%\"}') -ContentType 'application/json' -TimeoutSec 30; Write-Host '    [+] Added: %name%' } catch { Write-Host '    [-] Error adding player.' }"
echo.
echo    [+] When they run the scanner, it scans and self-deletes.
echo    [+] Report posts back to the server automatically.
echo.
pause
goto menu

:reports
cls
echo.
echo    SCAN REPORTS:
echo    ------------------------------------
echo.
powershell -NoProfile -Command "$headers = @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'}; try { $reports = Invoke-RestMethod -Uri '%RENDER_URL%/reports' -Headers $headers -TimeoutSec 30; if ($reports.Count -gt 0) { $i = 1; $reports | ForEach-Object { Write-Host ('    ' + $i + '. ' + $_); $i++ } } else { Write-Host '    No reports yet.' } } catch { Write-Host '    [-] Error fetching reports.' }"
echo.
echo    ------------------------------------
set /p rname="    Enter report name to view (or 'back'): "
if "%rname%"=="back" goto menu
if "%rname%"=="" goto menu

powershell -NoProfile -Command "$headers = @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'}; try { $r = Invoke-RestMethod -Uri ('%RENDER_URL%/report/%rname%') -Headers $headers -TimeoutSec 30; Write-Host ''; Write-Host '    ===================================='; Write-Host $r; Write-Host '    ====================================' } catch { Write-Host '    [-] Report not found or access denied.' }"
echo.
pause
goto menu

:add_checker
cls
echo.
echo    ADD CHECKER
echo.
set /p cname="    Name: "
if "%cname%"=="" goto menu

powershell -NoProfile -Command "Invoke-RestMethod -Uri '%RENDER_URL%/checker/add' -Method Post -Body '{\"name\":\"%cname%\",\"key\":\"PENDING\",\"role\":\"checker\",\"master_key\":\"%ADMIN_KEY%\"}' -ContentType 'application/json' -Headers @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'} -TimeoutSec 30" >nul 2>nul
echo.
echo    [+] Added checker: %cname%
echo    [+] Note: When they first launch the Service, it will permanently lock to their PC.
echo    [+] Give them: NatsuXAK Service.exe + scanner.exe
echo.
pause
goto menu

:remove_checker
cls
echo.
echo    REMOVE CHECKER
echo.
set /p cname="    Checker name: "
if "%cname%"=="" goto menu

powershell -NoProfile -Command "Invoke-RestMethod -Uri '%RENDER_URL%/checker/%cname%' -Method Delete -Headers @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'} -TimeoutSec 30" >nul 2>nul
echo.
echo    [+] Removed: %cname% (if existed)
echo.
pause
goto menu

:list_checkers
cls
echo.
echo    LIST CHECKERS
echo.
powershell -NoProfile -Command "$headers = @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'}; try { $c = Invoke-RestMethod -Uri '%RENDER_URL%/checkers' -Headers $headers -TimeoutSec 30; if (@($c).Count -gt 0) { @($c) | ForEach-Object { Write-Host ('    - ' + $_) } } else { Write-Host '    No checkers found.' } } catch { Write-Host '    [-] Error fetching checkers.' }"
echo.
pause
goto menu

:delete_report
cls
echo.
echo    DELETE REPORT
echo.
set /p drname="    Report name (player name): "
if "%drname%"=="" goto menu

powershell -NoProfile -Command "try { Invoke-RestMethod -Uri '%RENDER_URL%/report/%drname%' -Method Delete -Headers @{'X-Name'='%ADMIN_NAME%'; 'X-Key'='%ADMIN_KEY%'} -TimeoutSec 30; Write-Host '    [+] Deleted report: %drname%' } catch { Write-Host '    [-] Report not found or error.' }"
echo.
pause
goto menu

:server_status
cls
echo.
echo    SERVER STATUS
echo.
powershell -NoProfile -Command "try { $sw = [System.Diagnostics.Stopwatch]::StartNew(); $r = Invoke-RestMethod -Uri '%RENDER_URL%/health' -TimeoutSec 30; $sw.Stop(); Write-Host ('    Status: ONLINE'); Write-Host ('    Response time: ' + $sw.ElapsedMilliseconds + 'ms'); Write-Host ('    URL: %RENDER_URL%') } catch { Write-Host '    Status: OFFLINE or SLEEPING'; Write-Host '    The server may be waking up (30-50s on free tier).' }"
echo.
pause
goto menu

:exit
echo.
echo    [+] Admin panel closed.
exit
