# Use pre-built kmstool from GHCR
# Built from AWS's official aws-nitro-enclaves-sdk-c v0.4.3# Helper image to extract kmstool and libnsm using official AWS packages
# Helper image to build kmstool from source
# Helper image# Builder stage
FROM debian:bookworm-slim AS builder

WORKDIR /tmp

# Install build dependencies
# IMPORTANT: Do NOT install libssl-dev to avoid conflict with aws-lc
RUN apt-get update && apt-get install -y \
    git \
    cmake \
    ninja-build \
    build-essential \
    ca-certificates \
    curl \
    libjson-c-dev \
    golang \
    && rm -rf /var/lib/apt/lists/*

# Install Rust via rustup (Debian's cargo is too old - 1.63, we need 1.68+)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Setup build environment
ENV INSTALL_PATH=/usr/local
ENV CMAKE_PREFIX_PATH=$INSTALL_PATH
ENV LD_LIBRARY_PATH=$INSTALL_PATH/lib:$INSTALL_PATH/lib64

# 1. aws-lc (BoringSSL replacement)
RUN git clone --depth 1 -b v1.19.0 https://github.com/aws/aws-lc.git && \
    cmake -S aws-lc -B aws-lc/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release && \
    cmake --build aws-lc/build --target install && \
    rm -rf aws-lc

# 2. s2n-tls
RUN git clone --depth 1 -b v1.4.3 https://github.com/aws/s2n-tls.git && \
    cmake -S s2n-tls -B s2n-tls/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build s2n-tls/build --target install && \
    rm -rf s2n-tls

# 3. aws-c-common
RUN git clone --depth 1 -b v0.9.12 https://github.com/awslabs/aws-c-common.git && \
    cmake -S aws-c-common -B aws-c-common/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON && \
    cmake --build aws-c-common/build --target install && \
    rm -rf aws-c-common

# 4. aws-c-cal
RUN git clone --depth 1 -b v0.6.9 https://github.com/awslabs/aws-c-cal.git && \
    cmake -S aws-c-cal -B aws-c-cal/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-cal/build --target install && \
    rm -rf aws-c-cal

# 5. aws-c-io
RUN git clone --depth 1 -b v0.14.3 https://github.com/awslabs/aws-c-io.git && \
    cmake -S aws-c-io -B aws-c-io/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-io/build --target install && \
    rm -rf aws-c-io

# 6. aws-c-compression
RUN git clone --depth 1 -b v0.2.18 https://github.com/awslabs/aws-c-compression.git && \
    cmake -S aws-c-compression -B aws-c-compression/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-compression/build --target install && \
    rm -rf aws-c-compression

# 7. aws-c-http
RUN git clone --depth 1 -b v0.8.0 https://github.com/awslabs/aws-c-http.git && \
    cmake -S aws-c-http -B aws-c-http/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-http/build --target install && \
    rm -rf aws-c-http

# 7.5. aws-c-sdkutils (required by aws-c-auth)
RUN git clone --depth 1 -b v0.1.12 https://github.com/awslabs/aws-c-sdkutils.git && \
    cmake -S aws-c-sdkutils -B aws-c-sdkutils/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-sdkutils/build --target install && \
    rm -rf aws-c-sdkutils

# 8. aws-c-auth
RUN git clone --depth 1 -b v0.7.13 https://github.com/awslabs/aws-c-auth.git && \
    cmake -S aws-c-auth -B aws-c-auth/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON -DCMAKE_PREFIX_PATH=$INSTALL_PATH && \
    cmake --build aws-c-auth/build --target install && \
    rm -rf aws-c-auth

# 9. aws-nitro-enclaves-nsm-api
RUN git clone --depth 1 -b v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && cargo build --release --manifest-path Cargo.toml && \
    cp target/release/libnsm.so $INSTALL_PATH/lib/ && \
    mkdir -p $INSTALL_PATH/include && cp nsm.h $INSTALL_PATH/include/ && \
    cd .. && rm -rf aws-nitro-enclaves-nsm-api

# 10. aws-nitro-enclaves-sdk-c
RUN git clone --depth 1 -b v0.4.3 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cmake -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build -GNinja -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$INSTALL_PATH -DBUILD_SHARED_LIBS=ON && \
    cmake --build aws-nitro-enclaves-sdk-c/build --target install && \
    rm -rf aws-nitro-enclaves-sdk-c

# Production stage
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    iptables iproute2 dos2unix libjson-c5 \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir cryptography boto3 aws-nsm-interface

# Copy binaries and libs from builder
COPY --from=builder /usr/local/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli
COPY --from=builder /usr/local/lib /usr/lib
COPY --from=builder /usr/local/lib64 /usr/lib64

# Ensure linker cache is updated
RUN ldconfig

# Symlink Debian CA certs to the path expected by kmstool (built on AmazonLinux)
RUN mkdir -p /etc/pki/tls/certs && \
    ln -s /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt

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
