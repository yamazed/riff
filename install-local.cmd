@echo off
setlocal EnableExtensions

rem  Copy riff into this machine's local app data and run its first-time setup.
rem  Nothing is installed system-wide and no admin rights are needed: this is
rem  a file copy into your own profile.

set "SRC=%~dp0"
set "DEST=%LOCALAPPDATA%\riff"

echo.
echo   Installing riff for %USERNAME%
echo   from  %SRC%
echo   to    %DEST%
echo.

if not exist "%SRC%riff.exe" (
    echo   ERROR: riff.exe is not next to this script.
    echo   Run install-local.cmd from the folder that contains riff.exe.
    echo.
    pause
    exit /b 1
)

if not exist "%DEST%" mkdir "%DEST%" || (
    echo   ERROR: could not create %DEST%
    pause
    exit /b 1
)

copy /y "%SRC%riff.exe" "%DEST%\" >nul || (
    echo   ERROR: could not copy riff.exe. Is it already running?
    pause
    exit /b 1
)

rem  Only seed the rules file once, so an upgrade never overwrites local edits.
if exist "%SRC%rules.riff" (
    if exist "%DEST%\rules.riff" (
        echo   keeping your existing rules.riff
    ) else (
        copy /y "%SRC%rules.riff" "%DEST%\" >nul
        echo   copied starter rules.riff
    )
)

echo   copied riff.exe
echo.
echo   Next, from %DEST%:
echo.
echo     riff.exe setup          creates your own certificate authority,
echo                             offers to trust it, and points Windows at riff
echo     riff.exe run -s rules.riff
echo.
echo   To undo everything later:
echo.
echo     riff.exe proxy off
echo     riff.exe ca uninstall
echo     rmdir /s "%USERPROFILE%\.riff"
echo.

choice /c YN /n /m "  Run setup now? [Y/N] "
if errorlevel 2 goto :done
echo.
pushd "%DEST%"
riff.exe setup
popd

:done
echo.
pause
endlocal
