# Use pre-built kmstool from GHCR
# Built from AWS's official aws-nitro-enclaves-sdk-c v0.4.3# Helper image to extract kmstool and libnsm using official AWS packages
# Helper image to build kmstool from source
# Helper image to build kmstool from source
FROM amazonlinux:2023 AS kmstool-base
# Install build tools and dependencies
RUN dnf install -y \
    git cmake gcc make \
    tar gcc-c++ golang ninja-build \
    && dnf clean all

# Install Rust (required for nsm-api)
RUN curl https://sh.rustup.rs -sSf | sh -s -- -y --profile minimal --default-toolchain 1.71
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /tmp/crt-builder

# Build dependencies in order (Ref: aws-nitro-enclaves-sdk-c build docs)
RUN git clone --depth 1 -b v1.12.0 https://github.com/awslabs/aws-lc.git aws-lc && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja -DBUILD_TESTING=0 -S aws-lc -B aws-lc/build . && \
    go env -w GOPROXY=direct && \
    cmake --build aws-lc/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v1.3.46 https://github.com/aws/s2n-tls.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -S s2n-tls -B s2n-tls/build && \
    cmake --build s2n-tls/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.8.0 https://github.com/awslabs/aws-c-common.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-common -B aws-c-common/build && \
    cmake --build aws-c-common/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.1.2 https://github.com/awslabs/aws-c-sdkutils.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-sdkutils -B aws-c-sdkutils/build && \
    cmake --build aws-c-sdkutils/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.5.18 https://github.com/awslabs/aws-c-cal.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-cal -B aws-c-cal/build && \
    cmake --build aws-c-cal/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.11.0 https://github.com/awslabs/aws-c-io.git && \
    cmake -DUSE_VSOCK=1 -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-io -B aws-c-io/build && \
    cmake --build aws-c-io/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.2.14 http://github.com/awslabs/aws-c-compression.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-compression -B aws-c-compression/build && \
    cmake --build aws-c-compression/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.7.6 https://github.com/awslabs/aws-c-http.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-http -B aws-c-http/build && \
    cmake --build aws-c-http/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b v0.6.15 https://github.com/awslabs/aws-c-auth.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -GNinja -S aws-c-auth -B aws-c-auth/build && \
    cmake --build aws-c-auth/build --parallel $(nproc) --target install

RUN git clone --depth 1 -b json-c-0.16-20220414 https://github.com/json-c/json-c.git && \
    cmake -DCMAKE_PREFIX_PATH=/usr -DBUILD_TESTING=0 -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=OFF -GNinja -S json-c -B json-c/build && \
    cmake --build json-c/build --parallel $(nproc)  --target install

RUN git clone --depth 1 -b v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && cargo build --release --jobs $(nproc) -p nsm-lib && \
    mv target/release/libnsm.so /usr/lib64 && \
    mv target/release/nsm.h /usr/include

# Final SDK Build
RUN git clone --recursive https://github.com/aws/aws-nitro-enclaves-sdk-c.git aws-nitro-enclaves-sdk-c
RUN cmake -DCMAKE_PREFIX_PATH=/usr -DCMAKE_INSTALL_PREFIX=/usr -GNinja \
      -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build && \
    cmake --build aws-nitro-enclaves-sdk-c/build --parallel $(nproc) --target install

# Extract Binaries (match official path)
RUN cp /usr/bin/kmstool_enclave_cli /usr/bin/kmstool_enclave_cli_extracted && \
    cp /usr/lib64/libnsm.so /usr/lib64/libnsm.so_extracted

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
