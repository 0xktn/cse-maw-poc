#!/bin/sh
echo "============================================="
echo "ENCLAVE BOOTSTRAP STARTING"
echo "UserId: $(id)"
echo "PWD: $(pwd)"
echo "LS: $(ls -la)"
echo "PYTHON: $(which python)"
echo "ENV:"
env
echo "============================================="
echo "Starting Python app..."
/usr/local/bin/python -u app.py 2>&1
EXIT_CODE=$?
echo "Python exited with code: $EXIT_CODE"
echo "============================================="
# Keep alive if python fails
while true; do sleep 60; done
