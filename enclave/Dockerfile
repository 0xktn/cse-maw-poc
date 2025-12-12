# Builder: Amazon Linux 2023 (Has pre-built Nitro libs)
FROM amazonlinux:2023 AS builder

# Install build tools and pre-built Nitro libraries
# Added pkg-config to help CMake find the libraries
RUN dnf install -y \
    git \
    cmake \
    ninja-build \
    gcc \
    gcc-c++ \
    openssl-devel \
    aws-nitro-enclaves-cli-devel \
    pkg-config \
    && dnf clean all

# Setup build environment
# Point CMAKE_PREFIX_PATH to /usr where dnf installs libraries
ENV INSTALL_PATH=/usr/local
ENV CMAKE_PREFIX_PATH=/usr:$INSTALL_PATH

# Build ONLY the SDK-C Application (kmstool_enclave_cli)
# We link against the system-installed AWS libraries (from aws-nitro-enclaves-cli-devel)
RUN git clone --depth 1 -b v0.4.3 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cmake -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    && \
    cmake --build aws-nitro-enclaves-sdk-c/build --target install && \
    rm -rf aws-nitro-enclaves-sdk-c

# Final Stage: Amazon Linux 2023 (Runtime)
FROM amazonlinux:2023

# Install runtime dependencies (Python + Nitro CLI libs)
RUN dnf install -y \
    python3 \
    python3-pip \
    aws-nitro-enclaves-cli \
    findutils \
    && dnf clean all

# Copy artifact
COPY --from=builder /usr/local/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli

# Environment
WORKDIR /app
COPY app.py requirements.txt run.sh ./

# Setup Python environment
RUN python3 -m venv venv && \
    ./venv/bin/pip install --no-cache-dir -r requirements.txt

# Run
CMD ["./run.sh"]
