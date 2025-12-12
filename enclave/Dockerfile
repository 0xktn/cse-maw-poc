# Builder (Debian Bookworm)
FROM debian:bookworm-slim AS builder

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
ENV LD_LIBRARY_PATH=$INSTALL_PATH/lib:$INSTALL_PATH/lib64:$LD_LIBRARY_PATH
# Force C99/GNU99 standard to allow nested functions and permissive syntax
ENV CFLAGS="-std=gnu99 -Wno-error -w"

# 1. aws-lc (requires Go)
RUN git clone --depth 1 -b v1.19.0 https://github.com/aws/aws-lc.git && \
    cmake -S aws-lc -B aws-lc/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_SHARED_LIBS=ON \
    -DDISABLE_GO=OFF \
    && \
    go env -w GOPROXY=direct && \
    cmake --build aws-lc/build --target install && \
    rm -rf aws-lc

# 2. s2n-tls
RUN git clone --depth 1 -b v1.3.26 https://github.com/aws/s2n-tls.git && \
    cmake -S s2n-tls -B s2n-tls/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DUNSAFE_TREAT_WARNINGS_AS_ERRORS=OFF \
    && \
    cmake --build s2n-tls/build --target install && \
    rm -rf s2n-tls

# 3. aws-c-common
RUN git clone --depth 1 -b v0.9.12 https://github.com/awslabs/aws-c-common.git && \
    cmake -S aws-c-common -B aws-c-common/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-common/build --target install && \
    rm -rf aws-c-common

# 4. aws-c-cal
RUN git clone --depth 1 -b v0.6.11 https://github.com/awslabs/aws-c-cal.git && \
    cmake -S aws-c-cal -B aws-c-cal/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-cal/build --target install && \
    rm -rf aws-c-cal

# 5. aws-c-io
RUN git clone --depth 1 -b v0.13.1 https://github.com/awslabs/aws-c-io.git && \
    cmake -S aws-c-io -B aws-c-io/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-io/build --target install && \
    rm -rf aws-c-io

# 6. aws-c-compression
RUN git clone --depth 1 -b v0.2.16 https://github.com/awslabs/aws-c-compression.git && \
    cmake -S aws-c-compression -B aws-c-compression/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-compression/build --target install && \
    rm -rf aws-c-compression

# 7. aws-c-http
RUN git clone --depth 1 -b v0.8.0 https://github.com/awslabs/aws-c-http.git && \
    cmake -S aws-c-http -B aws-c-http/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-http/build --target install && \
    rm -rf aws-c-http

# 8. aws-c-sdkutils (REQUIRED by aws-c-auth)
RUN git clone --depth 1 -b v0.1.12 https://github.com/awslabs/aws-c-sdkutils.git && \
    cmake -S aws-c-sdkutils -B aws-c-sdkutils/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-sdkutils/build --target install && \
    rm -rf aws-c-sdkutils

# 9. aws-c-auth
RUN git clone --depth 1 -b v0.7.13 https://github.com/awslabs/aws-c-auth.git && \
    cmake -S aws-c-auth -B aws-c-auth/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    && \
    cmake --build aws-c-auth/build --target install && \
    rm -rf aws-c-auth

# 10. aws-nitro-enclaves-nsm-api (Rust)
# Uses rustup-installed cargo (1.68+).
# Use -p nsm-lib to ensure shared library is built.
RUN git clone --depth 1 -b v0.4.0 https://github.com/aws/aws-nitro-enclaves-nsm-api.git && \
    cd aws-nitro-enclaves-nsm-api && cargo build --release -p nsm-lib && \
    cp target/release/libnsm.so $INSTALL_PATH/lib/ && \
    mkdir -p $INSTALL_PATH/include && cp target/release/nsm.h $INSTALL_PATH/include/ && \
    cd .. && rm -rf aws-nitro-enclaves-nsm-api

# 11. aws-nitro-enclaves-sdk-c
# Fix: Disable -Werror with -DCMAKE_C_FLAGS="-w" to avoid deprecated API warnings failing the build
# Also disable AWS_WARNINGS_ARE_ERRORS
RUN git clone --depth 1 -b v0.4.3 https://github.com/aws/aws-nitro-enclaves-sdk-c.git && \
    cmake -S aws-nitro-enclaves-sdk-c -B aws-nitro-enclaves-sdk-c/build -GNinja \
    -DCMAKE_INSTALL_PREFIX=$INSTALL_PATH \
    -DBUILD_TESTING=OFF \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$INSTALL_PATH \
    -DBUILD_SHARED_LIBS=ON \
    -DAWS_WARNINGS_ARE_ERRORS=OFF \
    -DCMAKE_C_FLAGS="-w -Wno-error -Wno-pedantic -std=gnu99" \
    && \
    cmake --build aws-nitro-enclaves-sdk-c/build --target install && \
    rm -rf aws-nitro-enclaves-sdk-c

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

# Copy compiled artifacts from builder
COPY --from=builder /usr/local/bin /usr/bin/
COPY --from=builder /usr/local/lib /usr/lib/
COPY --from=builder /usr/local/include /usr/include/

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
