#!/bin/sh

# Log to null to avoid blocking on broken console pipe
exec 1>/dev/null
exec 2>/dev/null

# Setup Python environment
cd /app
source venv/bin/activate

# Run app
python3 -u app.py > /dev/null 2>&1

# Loop forever if app crashes
while true; do sleep 60; done
