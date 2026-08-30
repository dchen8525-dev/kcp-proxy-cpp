@echo off
cd /d "%~dp0"

if not exist "node_modules\" (
    echo Installing dependencies...
    call npm install
)

echo Starting KCP Proxy Client GUI...
call npm start