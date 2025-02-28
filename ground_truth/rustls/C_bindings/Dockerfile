FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    cmake \
    golang \
    musl-tools \
    openssl \
    && apt-get clean

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
# Add Rust to PATH
ENV PATH="/root/.cargo/bin:$PATH"

# Add the MUSL target for Rust
RUN rustup target add x86_64-unknown-linux-musl

# Install the cargo-cargo crate
RUN cargo install cargo-c --features=vendored-openssl

# Clone and build rustls-ffi
RUN git clone https://github.com/rustls/rustls-ffi
WORKDIR /rustls-ffi

COPY test_client_12_rustls_experimental.c /rustls-ffi/
COPY test_client_12_rustls_experimental_key_export.c /rustls-ffi/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source $HOME/.cargo/env' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of Rustls-ffi...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    # Build library and compile clients
    echo 'cargo capi install --release' >> /start.sh && \
    echo 'gcc test_client_12_rustls_experimental.c -o test_client_12_rustls_experimental -I/usr/local/include -L/usr/local/lib/x86_64-linux-gnu/ -lrustls' >> /start.sh && \
    echo 'gcc test_client_12_rustls_experimental_key_export.c -o test_client_12_rustls_experimental_key_export -I/usr/local/include -L/usr/local/lib/x86_64-linux-gnu/ -lrustls' >> /start.sh && \
    # Copy Clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_rustls_experimental test_client_12_rustls_experimental_key_export /compiled_clients/' >> /start.sh && \
    echo 'cp /usr/local/lib/x86_64-linux-gnu/*.so* /compiled_clients/libs/' >> /start.sh && \
    # Save version information
    echo 'echo "TLS Library: BotanSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \
    
    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]