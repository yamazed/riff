@echo off
setlocal EnableExtensions

rem  Launch a throwaway Chrome window wired directly to riff.
rem
rem  This does not touch Windows proxy settings at all, so it does not fight
rem  Zscaler (or any other endpoint agent that manages the system proxy), and
rem  there is nothing to restore afterwards. Only this window is captured —
rem  your normal browsing is untouched.
rem
rem      riff-browser.cmd  [starting-url]

set "PROXY=127.0.0.1:8888"
set "PROFILE=%LOCALAPPDATA%\riff\browser-profile"
set "START=%~1"
if "%START%"=="" set "START=about:blank"

set "CHROME="
for %%P in (
    "%ProgramFiles%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"
    "%LocalAppData%\Google\Chrome\Application\chrome.exe"
    "%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"
    "%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"
) do if not defined CHROME if exist %%P set "CHROME=%%~P"

if not defined CHROME (
    echo   ERROR: could not find Chrome or Edge in the usual places.
    echo   Edit this script and set CHROME to your browser's full path.
    pause
    exit /b 1
)

if not exist "%PROFILE%" mkdir "%PROFILE%" >nul 2>&1

echo.
echo   Launching a separate browser window through riff
echo     browser : %CHROME%
echo     proxy   : %PROXY%
echo     profile : %PROFILE%
echo.
echo   Only this window is captured. Close it when you're done.
echo   If pages show a certificate warning, run:  riff.exe ca install
echo.

rem  --proxy-bypass-list="<-loopback>" stops Chrome skipping the proxy for
rem  localhost, so local dev servers are captured too.
start "" "%CHROME%" ^
    --user-data-dir="%PROFILE%" ^
    --proxy-server="http://%PROXY%" ^
    --proxy-bypass-list="<-loopback>" ^
    --no-first-run ^
    --no-default-browser-check ^
    --new-window ^
    "%START%"

endlocal
