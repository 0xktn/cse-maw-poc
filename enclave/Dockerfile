# Use pre-built kmstool from GHCR
# Built from AWS's official aws-nitro-enclaves-sdk-c v0.4.3# Helper image to extract kmstool and libnsm using official AWS packages
# Helper image to build kmstool from source
FROM amazonlinux:2 AS kmstool-base
RUN yum install -y yum-utils && \
    amazon-linux-extras enable aws-nitro-enclaves-cli && \
    yum install -y git cmake3 gcc make && \
    yum clean all

# Build json-c from source (required by kmstool)
WORKDIR /tmp
RUN git clone https://github.com/json-c/json-c.git && \
    cd json-c && \
    git checkout json-c-0.16-20220414 && \
    mkdir build && cd build && \
    cmake3 .. && \
    make && \
    make install

WORKDIR /tmp/sdk
RUN git clone --recursive https://github.com/aws/aws-nitro-enclaves-sdk-c.git . && \
    mkdir build && cd build && \
    cmake3 .. -DNITRO_ENCLAVES_QS_LOG_LEVEL=3 && \
    make && \
    find /tmp/sdk -type f -name "libnsm.so" -exec cp {} /usr/lib64/libnsm.so \; && \
    ls -lR /tmp/sdk/bin && \
    cat /tmp/sdk/containers/Dockerfile.al2 && \
    exit 1

# Binary is now at /usr/bin/kmstool_enclave_cli
# or bin/kmstool_enclave_cli
# We will verify and find it in COPY stage (using wildcard if needed? No)
# SDK usually puts it in `build/bin` or `build/kmstool`
# Let's assume `build/kmstool/kmstool_enclave_cli` based on repo structure.

# Final stage: Add Python and our application
FROM python:3.11-slim

WORKDIR /app

# Copy kmstool binary and dependencies from base
COPY --from=kmstool-base /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
COPY --from=kmstool-base /usr/lib64/libnsm.so /usr/lib/libnsm.so

ENV LD_LIBRARY_PATH=/usr/lib:$LD_LIBRARY_PATH
COPY --from=kmstool-base /etc/pki/tls/certs /etc/pki/tls/certs

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
