#!/bin/bash
# Start Electron GUI in development mode

cd "$(dirname "$0")"

if [ ! -d "node_modules" ]; then
    echo "Installing dependencies..."
    npm install
fi

echo "Starting KCP Proxy Client GUI..."
npm start