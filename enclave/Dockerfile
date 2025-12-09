# Use pre-built kmstool from GHCR
# Built from AWS's official aws-nitro-enclaves-sdk-c v0.4.3 using Dockerfile.al2
FROM ghcr.io/0xktn/kmstool:v0.4.3 AS kmstool-base

# Final stage: Add Python and our application
FROM python:3.11-slim

WORKDIR /app

# Copy kmstool binary and dependencies from base
COPY --from=kmstool-base /usr/bin/kmstool_enclave /usr/bin/kmstool_enclave_cli
COPY --from=kmstool-base /usr/lib64/libnsm.so /usr/lib64/
COPY --from=kmstool-base /etc/pki/tls/certs /etc/pki/tls/certs

# Install runtime dependencies (if any)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir cryptography boto3

# Copy our application
COPY app.py .
COPY run.sh .
RUN chmod +x run.sh /usr/bin/kmstool_enclave_cli

# Entrypoint
CMD ["/app/run.sh"]
