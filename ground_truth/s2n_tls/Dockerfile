# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    python3 \
    libssl-dev \
    && apt-get clean

# Clone the s2n-tls repository
RUN git clone https://github.com/aws/s2n-tls.git

# Set the working directory to boringssl
WORKDIR /s2n-tls

# Copy the test client source files into the container
COPY test_client_12_s2ntls.c /s2n-tls/
COPY test_client_12_s2ntls_key_export.c /s2n-tls/
COPY test_client_13_s2ntls.c /s2n-tls/
COPY test_client_13_s2ntls_key_export.c /s2n-tls/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment
    
# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of s2n-tls...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build standard release version (static)
    echo 'cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=./s2n-tls-install' >> /start.sh && \
    echo 'cmake --build build -j $(nproc)' >> /start.sh && \
    echo 'cmake --install build' >> /start.sh && \

    # Compile static versions of test clients
    echo 'g++ test_client_12_s2ntls.c -o test_client_12_s2ntls -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_12_s2ntls_key_export.c -o test_client_12_s2ntls_key_export -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_s2ntls.c -o test_client_13_s2ntls -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_s2ntls_key_export.c -o test_client_13_s2ntls_key_export -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto -static' >> /start.sh && \
    echo 'cp test_client_12_s2ntls test_client_12_s2ntls_key_export test_client_13_s2ntls test_client_13_s2ntls_key_export /compiled_clients/' >> /start.sh && \
    
    # Build standar release version (shared)
    echo 'cmake . -Bbuild -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=On' >> /start.sh && \
    echo 'cmake --build build -j $(nproc)' >> /start.sh && \
    echo 'cmake --install build' >> /start.sh && \

    # Compile the dynamic verions of test clients
    echo 'g++ test_client_12_s2ntls.c -o test_client_12_s2ntls_dl -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto' >> /start.sh && \
    echo 'g++ test_client_12_s2ntls_key_export.c -o test_client_12_s2ntls_key_export_dl -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto' >> /start.sh && \
    echo 'g++ test_client_13_s2ntls.c -o test_client_13_s2ntls_dl -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto' >> /start.sh && \
    echo 'g++ test_client_13_s2ntls_key_export.c -o test_client_13_s2ntls_key_export_dl -I./s2n-tls-install/include -L./s2n-tls-install/lib -ls2n -lcrypto' >> /start.sh && \
    
    # Copy dynamic versions of test clients and sahred libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_s2ntls_dl test_client_12_s2ntls_key_export_dl test_client_13_s2ntls_dl test_client_13_s2ntls_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cp /s2n-tls/s2n-tls-install/lib/*.so* /compiled_clients/libs/' >> /start.sh && \

    # Save version information
    echo 'echo "TLS Library: s2n-tls" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]