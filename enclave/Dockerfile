# Use pre-built kmstool image from GHCR
FROM ghcr.io/0xktn/kmstool:v0.4.3 AS builder

# Final stage: Amazon Linux 2 runtime
FROM public.ecr.aws/amazonlinux/amazonlinux:2

# Install runtime dependencies
RUN yum install -y python3 python3-pip findutils && yum clean all

# Copy built artifacts from pre-built image
COPY --from=builder /usr/lib64/libnsm.so /usr/lib64/libnsm.so
COPY --from=builder /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli

# Copy application
WORKDIR /app
COPY app.py requirements.txt run.sh ./

# Setup Python environment
RUN python3 -m venv venv && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt && \
    chmod +x run.sh

CMD ["./run.sh"]
