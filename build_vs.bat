@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0"
cd /d "%ROOT%"

echo ========================================
echo  KCP Proxy Build (Windows)
echo ========================================

REM === Detect Visual Studio via vswhere ===
set "VS_FOUND="
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "!VSWHERE!" set "VSWHERE=%ProgramFiles%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "!VSWHERE!" (
    for /f "usebackq delims=" %%P in (`"!VSWHERE!" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do (
        if exist "%%P\VC\Auxiliary\Build\vcvarsall.bat" set "VS_FOUND=%%P\VC\Auxiliary\Build\vcvarsall.bat"
    )
)
if not defined VS_FOUND (
    echo ERROR: Visual Studio with C++ tools not found. Install VS 2019 or later.
    exit /b 1
)
goto :found_vs

:found_vs

REM === Save VCPKG_ROOT before vcvarsall may overwrite it ===
set "USER_VCPKG_ROOT=%VCPKG_ROOT%"

call "!VS_FOUND!" x64
if errorlevel 1 exit /b 1

REM === vcpkg setup: prefer user VCPKG_ROOT, then project-local, then bootstrap ===
set "USE_VCPKG="
if defined USER_VCPKG_ROOT if not "%USER_VCPKG_ROOT%"=="" (
    if exist "!USER_VCPKG_ROOT!\vcpkg.exe" (
        set "VCPKG_ROOT=!USER_VCPKG_ROOT!"
        set "USE_VCPKG=!USER_VCPKG_ROOT!"
    )
)
if not defined USE_VCPKG (
    if exist "%ROOT%vcpkg\vcpkg.exe" (
        set "VCPKG_ROOT=%ROOT%vcpkg"
        set "USE_VCPKG=%ROOT%vcpkg"
    )
)
if not defined USE_VCPKG (
    echo [3/5] Bootstrapping pinned vcpkg...
    set "VCPKG_COMMIT=c5a15727ee70fddf0296f0d8aafc3f58916fefac"
    git clone https://github.com/microsoft/vcpkg.git "%ROOT%vcpkg"
    if errorlevel 1 exit /b 1
    git -C "%ROOT%vcpkg" checkout --detach !VCPKG_COMMIT!
    if errorlevel 1 exit /b 1
    call "%ROOT%vcpkg\bootstrap-vcpkg.bat" -disableMetrics
    if errorlevel 1 exit /b 1
    set "VCPKG_ROOT=%ROOT%vcpkg"
)
echo [2/5] Using vcpkg at !VCPKG_ROOT!
if not exist "!VCPKG_ROOT!\vcpkg.exe" (
    echo ERROR: vcpkg.exe not found under !VCPKG_ROOT!
    exit /b 1
)


echo [3/5] Installing dependencies...
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; $vcpkg=Start-Process \"%VCPKG_ROOT%\\vcpkg.exe\" -ArgumentList 'install','--triplet=x64-windows' -NoNewWindow -PassThru -Wait; if($vcpkg.ExitCode -ne 0){ exit $vcpkg.ExitCode }"
if errorlevel 1 exit /b 1

REM === Configure and build ===
echo [4/5] Configuring and building...
cmake --preset default
if errorlevel 1 exit /b 1
cmake --build --preset release --parallel
if errorlevel 1 exit /b 1

REM Run tests through CTest with an explicit multi-config selection.
ctest --test-dir build -C Release --output-on-failure
if errorlevel 1 exit /b 1

echo.
set "OUTDIR=%ROOT%bin\windows"
if not exist "%OUTDIR%" mkdir "%OUTDIR%"
copy /Y "build\Release\kcp-proxy-server.exe" "%OUTDIR%\" >nul
copy /Y "build\Release\kcp-proxy-client.exe" "%OUTDIR%\" >nul

REM === Copy OpenSSL DLLs (required for runtime) ===
set "OPENSSL_DLLS=libcrypto-3-x64.dll libssl-3-x64.dll"
REM Manifest-mode vcpkg installs under build\vcpkg_installed; the legacy
REM installed\ layout under VCPKG_ROOT is only used in classic mode. Probe
REM the manifest location first, then fall back.
set "DLL_SRC=%ROOT%build\vcpkg_installed\x64-windows\bin"
if not exist "!DLL_SRC!\libcrypto-3-x64.dll" set "DLL_SRC=%VCPKG_ROOT%\installed\x64-windows\bin"
for %%D in (%OPENSSL_DLLS%) do (
    if not exist "!DLL_SRC!\%%D" (
        echo ERROR: required OpenSSL DLL missing: %%D
        exit /b 1
    )
    copy /Y "!DLL_SRC!\%%D" "%OUTDIR%\" >nul
    if errorlevel 1 exit /b 1
)

dir /b "%OUTDIR%\"
echo.
echo Done. Output: %OUTDIR%
echo Server: kcp-proxy-server.exe -k ^<key^>
echo Client: kcp-proxy-client.exe -s ^<host^> -k ^<key^>
