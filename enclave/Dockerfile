# Use pre-built kmstool image as base for artifacts
FROM ghcr.io/0xktn/kmstool:v0.4.3 AS builder

# Final Stage: Run the Application
FROM debian:bookworm-slim

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libjson-c5 \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy compiled artifacts from builder (pre-built image)
COPY --from=builder /usr/local/bin /usr/bin/
COPY --from=builder /usr/local/lib /usr/lib/
COPY --from=builder /usr/local/include /usr/include/
COPY --from=builder /usr/local/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli

# Ensure library path is set
ENV LD_LIBRARY_PATH=/usr/lib

# Copy application files
WORKDIR /app
COPY app.py requirements.txt run.sh ./

# Setup Python environment
RUN python3 -m venv venv && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt

# Run
CMD ["./run.sh"]
