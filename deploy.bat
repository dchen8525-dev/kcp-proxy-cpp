@echo off
:: Thin forwarder -> scripts\deploy\deploy.py (Python3, cross-platform)
set SCRIPT_DIR=%~dp0
set DEPLOY_PY=%SCRIPT_DIR%scripts\deploy\deploy.py

if not exist "%DEPLOY_PY%" (
    echo Error: deploy script not found at %DEPLOY_PY%
    exit /b 1
)

where python >nul 2>nul
if %errorlevel%==0 (
    python "%DEPLOY_PY%" %*
    exit /b %errorlevel%
)

where py >nul 2>nul
if %errorlevel%==0 (
    py "%DEPLOY_PY%" %*
    exit /b %errorlevel%
)

echo Error: python not found. Install Python 3 to use the deploy script.
exit /b 1
