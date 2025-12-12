#!/bin/sh

# Log to console
exec 2>&1

echo "[ENCLAVE] Starting Python app..." > /dev/console

# Setup Python environment
cd /app
source venv/bin/activate

# Run app
python3 -u app.py > /dev/console 2>&1

# Loop forever if app crashes
while true; do sleep 60; done
