#!/bin/sh
# Force all output to the enclave console
exec python3.11 -u /app/app.py >/tmp/enclave.log 2>&1
cat /tmp/enclave.log > /dev/console

echo "[ENCLAVE] Starting..."
echo "[ENCLAVE] Environment: $(uname -a)"

# Export unbuffered python
export PYTHONUNBUFFERED=1

# Run Python app
# Use exec to ensure signals are passed to the python process
# Run the application with unbuffered output
exec python3.11 -u /app/app.py
