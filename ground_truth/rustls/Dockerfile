# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    build-essential \
    && apt-get clean

# Install Rust and Musl target (-y for autimatically selecting defaults)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
RUN /root/.cargo/bin/rustup target add x86_64-unknown-linux-musl
RUN apt update && apt install -y musl-tools


# Set Working Directory to rustls
RUN mkdir /rustls
WORKDIR /rustls



# TODO: make latest version available 
# Copy the test client source files into the container
COPY test_client_12_rustls/ /rustls/test_client_12_rustls/
COPY test_client_13_rustls/ /rustls/test_client_13_rustls/
COPY test_client_12_rustls_key_export/ /rustls/test_client_12_rustls_key_export/
COPY test_client_13_rustls_key_export/ /rustls/test_client_13_rustls_key_export/

# This startup script will build the test clients
# If the argument is "latest", cargo will update the package to the latest version of rustls
# Otherwise, the test clients will be built with the 0.23.14 version of rustls
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source $HOME/.cargo/env' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '  echo "Building latest version of rustls...";' >> /start.sh && \
    echo '  cd ./test_client_12_rustls' >> /start.sh && \
    echo '  cargo update --package rustls' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cd ../test_client_13_rustls' >> /start.sh && \
    echo '  cargo update --package rustls' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_13_rustls /compiled_clients/' >> /start.sh && \
    echo '  cd ../test_client_12_rustls_key_export' >> /start.sh && \
    echo '  cargo update --package rustls' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_12_rustls_key_export /compiled_clients/' >> /start.sh && \
    echo '  cd ../test_client_13_rustls_key_export' >> /start.sh && \
    echo '  cargo update --package rustls' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_13_rustls_key_export /compiled_clients/' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '  cd ./test_client_12_rustls' >> /start.sh && \
    echo '  echo "[package]\nname = \"test_client_12_rustls\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nrustls = \"0.23.14\"" > Cargo.toml' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_12_rustls /compiled_clients/' >> /start.sh && \
    echo '  cd ../test_client_13_rustls' >> /start.sh && \
    echo '  echo "[package]\nname = \"test_client_13_rustls\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nrustls = \"0.23.14\"" > Cargo.toml' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_13_rustls /compiled_clients/' >> /start.sh && \
    echo '  cd ../test_client_12_rustls_key_export' >> /start.sh && \
    echo '  echo "[package]\nname = \"test_client_12_rustls_key_export\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhex = \"0.4\"\nrustls = \">0.23.14\"" > Cargo.toml' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_12_rustls_key_export /compiled_clients/' >> /start.sh && \
    echo '  cd ../test_client_13_rustls_key_export' >> /start.sh && \
    echo '  echo "[package]\nname = \"test_client_13_rustls_key_export\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nhex = \"0.4\"\nrustls = \">0.23.14\"" > Cargo.toml' >> /start.sh && \
    echo '  cargo build --target x86_64-unknown-linux-musl' >> /start.sh && \
    echo '  cp target/x86_64-unknown-linux-musl/debug/test_client_13_rustls_key_export /compiled_clients/' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    echo 'grep "name = \\"rustls\\"" /rustls/test_client_12_rustls/Cargo.lock -A 1 | grep "version =" | sed "s/.*version = \\"\\(.*\\)\\"/rustls version: \\1/" > /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh

# Command for running the startup script with arguments
CMD ["/start.sh"]