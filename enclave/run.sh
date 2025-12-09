#!/bin/sh

# Setup log file
touch /tmp/enclave.log

# Background broadcaster: Spams console with state every 2s so we can't miss it
(
  while true; do
    echo "=== [$(date)] ENCLAVE MONITOR ===" > /dev/console
    echo "--- PROCESSES ---" > /dev/console
    ps -ef > /dev/console
    echo "--- LOG TAIL (20 lines) ---" > /dev/console
    tail -n 20 /tmp/enclave.log > /dev/console
    sleep 2
  done
) &

# Run Python app with standard logging
echo "[ENCLAVE] Verifying KMSTool..." > /dev/console
/usr/bin/kmstool_enclave_cli --help > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[ENCLAVE] KMSTool FAILED to execute!" > /dev/console
    echo "[ENCLAVE] KMSTool FAILED to execute!" > /tmp/enclave.log
else
    echo "[ENCLAVE] KMSTool looks healthy." > /dev/console
fi

echo "[ENCLAVE] Starting Python app..." > /dev/console
echo "[ENCLAVE] Starting Python app..." > /tmp/enclave.log

# Use python3 (symlink to 3.11 in slim)
# Unbuffered output
python3 -u /app/app.py >> /tmp/enclave.log 2>&1
EXIT_CODE=$?

echo "[ENCLAVE] App exited with code $EXIT_CODE" >> /tmp/enclave.log
echo "[ENCLAVE] App exited with code $EXIT_CODE" > /dev/console

# Dump log to console for debugging
cat /tmp/enclave.log > /dev/console

# DEATH RATTLE: Send logs to Host (CID 3) Port 8000
echo "[ENCLAVE] Sending logs to host..."
cat /tmp/enclave.log | socat - VSOCK-CONNECT:3:8000

# Drop into shell if it crashed, or exit
exit $EXIT_CODE
