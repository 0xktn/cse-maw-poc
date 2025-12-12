#!/bin/sh

# Log setup
touch /tmp/app.log

# Non-blocking log streamer
(
    tail -F /tmp/app.log > /dev/console 2>&1
) &

echo "[ENCLAVE] Starting Python app (Logged to /tmp/app.log)..." > /tmp/app.log

# Setup Python environment
cd /app
source venv/bin/activate

# Run app directing output to file (non-blocking)
python3 -u simple.py >> /tmp/app.log 2>&1

# Loop forever if app crashes
echo "[ENCLAVE] App crashed with code $?" >> /tmp/app.log
while true; do sleep 60; done
