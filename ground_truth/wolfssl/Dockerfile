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
    autoconf \
    automake \
    libtool \
    && apt-get clean

# Clone the wolfSSL repository
RUN git clone https://github.com/wolfSSL/wolfssl.git

# Set the working directory to wolfssl
WORKDIR /wolfssl

# Copy the test client source files into the container
COPY test_client_12_wolfssl.c /wolfssl/
COPY test_client_13_wolfssl.c /wolfssl/
COPY test_client_12_wolfssl_key_export.c /wolfssl/
COPY test_client_13_wolfssl_key_export.c /wolfssl/


# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of wolfSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    
    # Build standard release (static)
    echo './autogen.sh' >> /start.sh && \
    echo './configure --enable-static --disable-shared' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # Compile standard test clients (static)
    echo 'g++ test_client_12_wolfssl.c -o test_client_12_wolfssl -L/usr/local/lib -lwolfssl -static' >> /start.sh && \
    echo 'g++ test_client_13_wolfssl.c -o test_client_13_wolfssl -L/usr/local/lib -lwolfssl -static' >> /start.sh && \
    echo 'cp test_client_12_wolfssl test_client_13_wolfssl /compiled_clients/' >> /start.sh && \

    # Build version with key-export (static)
    echo 'make uninstall' >> /start.sh && \
    echo 'make clean' >> /start.sh && \
    echo './configure --enable-static --disable-shared --enable-keylog-export' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # Compile export test clients (static)
    echo 'g++ test_client_12_wolfssl_key_export.c -o test_client_12_wolfssl_key_export -L/usr/local/lib -lwolfssl -DWOLFSSL_SNIFFER_KEYLOGFILE -static' >> /start.sh && \
    echo 'g++ test_client_13_wolfssl_key_export.c -o test_client_13_wolfssl_key_export -L/usr/local/lib -lwolfssl -DWOLFSSL_SNIFFER_KEYLOGFILE -static' >> /start.sh && \
    echo 'cp test_client_12_wolfssl_key_export test_client_13_wolfssl_key_export /compiled_clients/' >> /start.sh && \
    
    # Build standard release (shared)
    echo 'make uninstall' >> /start.sh && \
    echo 'make clean' >> /start.sh && \
    echo './configure --enable-shared --disable-static' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # Compile standard test clients (dynamic)
    echo 'g++ test_client_12_wolfssl.c -o test_client_12_wolfssl_dl -L/usr/local/lib -lwolfssl' >> /start.sh && \
    echo 'g++ test_client_13_wolfssl.c -o test_client_13_wolfssl_dl -L/usr/local/lib -lwolfssl' >> /start.sh && \

    # Build version with key-export (shared)
    echo 'make uninstall' >> /start.sh && \
    echo 'make clean' >> /start.sh && \
    echo './configure --enable-shared --disable-static --enable-keylog-export' >> /start.sh && \
    echo 'make' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # compile export test clients (dynamic)
    echo 'g++ test_client_12_wolfssl_key_export.c -o test_client_12_wolfssl_key_export_dl -L/usr/local/lib -lwolfssl -DWOLFSSL_SNIFFER_KEYLOGFILE' >> /start.sh && \
    echo 'g++ test_client_13_wolfssl_key_export.c -o test_client_13_wolfssl_key_export_dl -L/usr/local/lib -lwolfssl -DWOLFSSL_SNIFFER_KEYLOGFILE' >> /start.sh && \
    
    # Copy dynamic versions of the test clinets and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_wolfssl_dl test_client_13_wolfssl_dl test_client_12_wolfssl_key_export_dl test_client_13_wolfssl_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cp /usr/local/lib/*.so* /compiled_clients/libs/' >> /start.sh && \

    # Save version information
    echo 'echo "TLS Library: wolfSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]