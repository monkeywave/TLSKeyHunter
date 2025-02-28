#Use the offical Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    libssl-dev \
    cmake \
    python3 \
    automake \
    autoconf \
    libtool \
    perl \
    && apt-get clean

# Clone the LibreSSL repository
RUN git clone https://github.com/libressl/portable.git

# Set the working directory to libressl
WORKDIR /portable

# Copy the test client source files into the container
COPY test_client_12_libressl.c /portable/
COPY test_client_13_libressl.c /portable/
COPY test_client_12_libressl_key_export.c /portable/
COPY test_client_13_libressl_key_export.c /portable/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of LibreSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build standard release version (static)
    echo './autogen.sh' >> /start.sh && \
    echo './configure --enable-static --disable-shared' >> /start.sh && \
    echo 'make install' >> /start.sh && \
    echo 'g++ test_client_12_libressl.c -o test_client_12_libressl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_libressl.c -o test_client_13_libressl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_12_libressl_key_export.c -o test_client_12_libressl_key_export -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_libressl_key_export.c -o test_client_13_libressl_key_export -I/usr/local/include -L/usr/local/lib -lssl -lcrypto -static' >> /start.sh && \
    echo 'cp  test_client_12_libressl test_client_13_libressl test_client_12_libressl_key_export test_client_13_libressl_key_export /compiled_clients/' >> /start.sh && \
    
    # Build shared release version
    echo 'make clean' >> /start.sh && \
    echo './configure --enable-shared --disable-static' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # Compile dynamic versions of test clients
    echo 'g++ test_client_12_libressl.c -o test_client_12_libressl_dl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto' >> /start.sh && \
    echo 'g++ test_client_13_libressl.c -o test_client_13_libressl_dl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto' >> /start.sh && \
    echo 'g++ test_client_12_libressl_key_export.c -o test_client_12_libressl_key_export_dl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto' >> /start.sh && \
    echo 'g++ test_client_13_libressl_key_export.c -o test_client_13_libressl_key_export_dl -I/usr/local/include -L/usr/local/lib -lssl -lcrypto' >> /start.sh && \
    
    # Copy dynamic version of test clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp  test_client_12_libressl_dl test_client_13_libressl_dl test_client_12_libressl_key_export_dl test_client_13_libressl_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cp /usr/local/lib/*.so* /compiled_clients/libs/' >> /start.sh && \
    
    # Save version information
    echo 'echo "TLS Library: LibreSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh

# Set CMD to execute the startup script
CMD ["/start.sh"]