# Use pre-built kmstool from GHCR
# Built from AWS's official aws-nitro-enclaves-sdk-c v0.4.3# Helper image to extract kmstool and libnsm using official AWS packages
# Helper image to build kmstool from source
# Helper image# Use pre-built kmstool from GHCR
FROM ghcr.io/0xktn/kmstool:v0.4.3 AS kmstool-base

# Production stage: Add Python and our application
FROM python:3.11-slim

WORKDIR /app

# DEBUG: Extact and find files
COPY --from=kmstool-base / /tmp/extracted_fs/
RUN echo "DEBUG: Finding libnsm.so" && find /tmp/extracted_fs -name libnsm.so
RUN echo "DEBUG: Finding kmstool" && find /tmp/extracted_fs -name kmstool*
RUN echo "DEBUG: FORCE FAIL" && exit 1

# Copy kmstool binary and dependencies from base
 # COPY --from=kmstool-base /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
 # COPY --from=kmstool-base /usr/lib/libnsm.so /usr/lib/libnsm.so

# Symlink Debian CA certs to the path expected by kmstool (built on AmazonLinux)
RUN mkdir -p /etc/pki/tls/certs && \
    ln -s /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt

# Install runtime dependencies (if any)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates socat \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir cryptography boto3

# Copy our application
COPY app.py .
COPY run.sh .
RUN chmod +x run.sh /usr/bin/kmstool_enclave_cli

# Entrypoint
CMD ["/app/run.sh"]
