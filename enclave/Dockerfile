# Stage 1: Build kmstool_enclave_cli from AWS SDK
FROM amazonlinux:2023 AS kmstool-builder

RUN dnf install -y git cmake3 gcc gcc-c++ make openssl-devel curl-devel json-c-devel && \
    dnf clean all

RUN git clone --depth 1 https://github.com/aws/aws-nitro-enclaves-sdk-c.git /sdk
WORKDIR /sdk

# Build the SDK and kmstool
RUN cmake3 -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=/usr . && \
    make -j$(nproc) kmstool_enclave_cli

# Stage 2: Python Application
FROM amazonlinux:2023

WORKDIR /app

# Copy kmstool binary from builder
COPY --from=kmstool-builder /sdk/bin/kmstool-enclave-cli/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
RUN chmod +x /usr/bin/kmstool_enclave_cli

# Install Python 3.11 and runtime dependencies
RUN dnf install -y python3.11 python3.11-pip openssl json-c curl && dnf clean all

# Install Python dependencies
RUN pip3.11 install --no-cache-dir cryptography boto3

# Copy application
COPY app.py .
COPY run.sh .
RUN chmod +x run.sh

# Entrypoint
CMD ["/app/run.sh"]
