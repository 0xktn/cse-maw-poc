FROM python:3.11-alpine

WORKDIR /app

# Install simple dependencies just for test
RUN pip install cryptography boto3

# Inline command to avoid file path issues
CMD ["python3", "-u", "-c", "import sys; import time; print('HELLO ALPINE ENCLAVE'); print(sys.version); time.sleep(3600)"]
