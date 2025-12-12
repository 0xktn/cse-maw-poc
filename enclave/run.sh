#!/bin/sh

# Log everything to console
exec 2>&1

echo "[ENCLAVE] ==============================" > /dev/console
echo "[ENCLAVE] Enclave starting up..." > /dev/console
echo "[ENCLAVE] ==============================" > /dev/console

# Setup log file
touch /tmp/enclave.log

# Background listener: echo status to console every 5s
(
  while true; do
    echo "=== [$(date)] ENCLAVE HEARTBEAT ===" > /dev/console
    ps aux > /dev/console 2>&1 || echo "ps failed" > /dev/console
    tail -20 /tmp/enclave.log > /dev/console 2>&1 || true
    sleep 5
  done
) &

echo "[ENCLAVE] Starting Python app..." | tee -a /tmp/enclave.log > /dev/console

# Activate venv and run app
cd /app
source venv/bin/activate
python3 -u app.py >> /tmp/enclave.log 2>&1
EXIT_CODE=$?

echo "[ENCLAVE] App exited with code $EXIT_CODE" | tee -a /tmp/enclave.log > /dev/console

# Keep alive for debugging
echo "[ENCLAVE] Entering keep-alive loop..." > /dev/console
while true; do
  sleep 60
done
