@echo off
REM Local runtime launcher (Windows counterpart of start.sh).
REM
REM Usage:
REM   scripts\runtime\start.bat server [suffix]
REM   scripts\runtime\start.bat client HOST [suffix]
REM
REM The key is derived as YYYYMMDD (Beijing time) + suffix and passed through
REM KCP_PROXY_KEY, never -k: a process command line is readable by every local
REM user, the environment only by the same user.

setlocal

set "SCRIPT_DIR=%~dp0"
set "SERVER_PORT=8388"
set "SERVER_HOST=0.0.0.0"
set "CLIENT_LISTEN_HOST=127.0.0.1"
set "CLIENT_LISTEN_PORT=1080"
set "LOG_LEVEL=INFO"

set "MODE=%~1"
if "%MODE%"=="" goto :usage

if /i "%MODE%"=="server" (
    set "HOST="
    set "SUFFIX=%~2"
    set "NAME=kcp-proxy-server.exe"
) else if /i "%MODE%"=="client" (
    set "HOST=%~2"
    set "SUFFIX=%~3"
    set "NAME=kcp-proxy-client.exe"
) else (
    goto :usage
)

if /i "%MODE%"=="client" if "%HOST%"=="" goto :usage

if "%SUFFIX%"=="" (
    echo Error: a suffix of 8-128 chars of [A-Za-z0-9._-] is required >&2
    goto :usage
)

REM Validate the suffix and derive the Beijing date in PowerShell. The suffix
REM travels through the environment so a value with cmd metacharacters cannot
REM inject commands into the -Command string.
set "KCP_SUFFIX=%SUFFIX%"
set "KCP_DATE_PS=$ProgressPreference='SilentlyContinue'; if ($env:KCP_SUFFIX -notmatch '^[A-Za-z0-9._-]{8,128}$') { exit 1 }; (Get-Date).ToUniversalTime().AddHours(8).ToString('yyyyMMdd')"
for /f "usebackq delims=" %%D in (`powershell -NoProfile -Command "%KCP_DATE_PS%"`) do set "DATE_BEIJING=%%D"
if not defined DATE_BEIJING (
    echo Error: suffix must be 8-128 chars of [A-Za-z0-9._-] >&2
    exit /b 1
)

REM Binary lookup: next to this script (release layout), bin\windows (build
REM output), then a local CMake build tree.
set "BIN="
for %%P in (
    "%SCRIPT_DIR%%NAME%"
    "%SCRIPT_DIR%..\%NAME%"
    "%SCRIPT_DIR%..\..\bin\windows\%NAME%"
    "%SCRIPT_DIR%..\..\build\Release\%NAME%"
    "%SCRIPT_DIR%..\..\build\%NAME%"
) do if not defined BIN if exist "%%~fP" set "BIN=%%~fP"

if not defined BIN (
    echo Error: %NAME% not found; run build_vs.bat first or unpack a release >&2
    exit /b 1
)

set "KCP_PROXY_KEY=%DATE_BEIJING%%SUFFIX%"

if /i "%MODE%"=="server" (
    echo Starting server: UDP %SERVER_HOST%:%SERVER_PORT% >&2
    "%BIN%" -p %SERVER_PORT% -H %SERVER_HOST% -L %LOG_LEVEL%
) else (
    echo Starting client: server=%HOST%:%SERVER_PORT% socks5=%CLIENT_LISTEN_HOST%:%CLIENT_LISTEN_PORT% >&2
    "%BIN%" -s %HOST% -p %SERVER_PORT% -H %CLIENT_LISTEN_HOST% -l %CLIENT_LISTEN_PORT% -L %LOG_LEVEL%
)
exit /b %ERRORLEVEL%

:usage
echo Usage: %~nx0 server [suffix] >&2
echo        %~nx0 client HOST [suffix] >&2
echo   suffix: 8-128 chars of [A-Za-z0-9._-] ^(the key is Beijing date + suffix^) >&2
exit /b 1
