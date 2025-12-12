# Builder: Amazon Linux 2 (Official Enclave OS)
FROM amazonlinux:2 AS builder

# Install amazon-linux-extras and enable nitro-enclaves
RUN amazon-linux-extras install aws-nitro-enclaves-cli -y && \
    yum install -y \
    git \
    gcc \
    gcc-c++ \
    cmake \
    ninja-build \
    aws-nitro-enclaves-cli-devel \
    openssl-devel \
    pkgconfig \
    yum-utils \
    && yum clean all

# Build dependencies/tools if not present in AL2 default repos
# AL2 cmake is often old (v2.8), we might need v3.
# Checking if cmake3 is available
RUN yum install -y cmake3 && \
    ln -sf /usr/bin/cmake3 /usr/bin/cmake

# Setup build environment
ENV INSTALL_PATH=/usr/local
ENV CMAKE_PREFIX_PATH=/usr:$INSTALL_PATH

# Build ONLY the SDK-C Application (kmstool_enclave_cli)
RUN git clone --depth 1 -b v0.4.3 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cmake3 -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=OFF \
    && \
    cmake3 --build aws-nitro-enclaves-sdk-c/build --target install && \
    rm -rf aws-nitro-enclaves-sdk-c

# Final Stage: Amazon Linux 2
FROM amazonlinux:2

# Install runtime dependencies
RUN amazon-linux-extras install aws-nitro-enclaves-cli -y && \
    yum install -y \
    python3 \
    python3-pip \
    findutils \
    && yum clean all

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
