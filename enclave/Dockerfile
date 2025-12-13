# Use pre-built kmstool image from GHCR
FROM ghcr.io/0xktn/kmstool:v0.4.3 AS builder

# Final stage: Amazon Linux 2023 runtime
FROM public.ecr.aws/amazonlinux/amazonlinux:2023

# Install runtime dependencies
RUN dnf install -y python3 python3-pip findutils && dnf clean all

# Copy built artifacts from pre-built image
COPY --from=builder /usr/lib64/libnsm.so /usr/lib64/libnsm.so
COPY --from=builder /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli

# Copy application to /app
RUN mkdir -p /app
COPY enclave/app.py enclave/requirements.txt enclave/run.sh /app/

# Setup Python environment
RUN cd /app && \
    python3 -m venv venv && \
    ./venv/bin/pip install --no-cache-dir --upgrade pip && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt && \
    chmod +x run.sh

CMD ["/app/run.sh"]
