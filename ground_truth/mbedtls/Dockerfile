#Use the offical Ubuntu base image
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
    python3-pip \
    python3.12-venv \
    && apt-get clean

# Clone the mbedTLS repository
RUN git clone https://github.com/Mbed-TLS/mbedtls.git

# Set the working directory to mbedtls
WORKDIR /mbedtls

# This is temporary needed to build the clients. 
# There has been made changes to the mbedtls repository, causing the compilation to fail.
# Until figured out how to fix the compilation, this commit is used to build the clients.
RUN git checkout v3.6.0-1031-g8c95999b3;


# Copy the test client source files into the container
COPY test_client_12_mbedtls.c /mbedtls/
COPY test_client_12_mbedtls_key_export.c /mbedtls/
COPY test_client_13_mbedtls.c /mbedtls/
COPY test_client_13_mbedtls_key_export.c /mbedtls/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of MbedTLStls...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build standard release (static)
    echo 'git submodule update --init' >> /start.sh && \
    echo 'python3 -m venv venv' >> /start.sh && \
    echo 'source venv/bin/activate' >> /start.sh && \
    echo 'pip install --upgrade pip' >> /start.sh && \
    echo 'python3 -m pip install -r ./scripts/basic.requirements.txt' >> /start.sh && \
    echo 'cmake .' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \
    echo 'g++ test_client_12_mbedtls.c -o test_client_12_mbedtls -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto -static' >> /start.sh && \
    echo 'g++ test_client_12_mbedtls_key_export.c -o test_client_12_mbedtls_key_export -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_mbedtls.c -o test_client_13_mbedtls -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_mbedtls_key_export.c -o test_client_13_mbedtls_key_export -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto -static' >> /start.sh && \
    echo 'cp test_client_12_mbedtls test_client_12_mbedtls_key_export test_client_13_mbedtls test_client_13_mbedtls_key_export /compiled_clients/' >> /start.sh && \
    
    # Build standard release (shared)
    echo 'cmake -DUSE_SHARED_MBEDTLS_LIBRARY=On .' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \ 

    # Compile dynamic version of test clients
    echo 'g++ test_client_12_mbedtls.c -o test_client_12_mbedtls_dl -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto' >> /start.sh && \
    echo 'g++ test_client_12_mbedtls_key_export.c -o test_client_12_mbedtls_key_export_dl -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto' >> /start.sh && \
    echo 'g++ test_client_13_mbedtls.c -o test_client_13_mbedtls_dl -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto' >> /start.sh && \
    echo 'g++ test_client_13_mbedtls_key_export.c -o test_client_13_mbedtls_key_export_dl -I/usr/local/include -L/usr/local/lib -lmbedtls -lmbedx509 -lmbedcrypto' >> /start.sh && \
    
    # Copy dynamic versions of test clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_mbedtls_dl test_client_12_mbedtls_key_export_dl test_client_13_mbedtls_dl test_client_13_mbedtls_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cp /usr/local/lib/*.so* /compiled_clients/libs/' >> /start.sh && \

    # Save version information
    echo 'echo "TLS Library: MbedTLS" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]