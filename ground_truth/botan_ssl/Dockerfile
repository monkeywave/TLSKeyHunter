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
    && apt-get clean

# Clone the BotanSSL repository
RUN git clone https://github.com/randombit/botan.git

# Set the working directory to botan
WORKDIR /botan

# Copy the test client source files into the container
COPY test_client_12_botanssl.cpp /botan/
COPY test_client_13_botanssl.cpp /botan/
COPY test_client_12_botanssl_key_export.cpp /botan/
COPY test_client_13_botanssl_key_export.cpp /botan/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of BotanSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build static release
    echo './configure.py --disable-shared-library' >> /start.sh && \
    echo 'make all -j$(nproc)' >> /start.sh && \
    echo 'make install' >> /start.sh && \

    # Compile and copy static versions of test clients
    echo 'g++ test_client_12_botanssl.cpp -o test_client_12_botanssl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3 -static' >> /start.sh && \
    echo 'g++ test_client_13_botanssl.cpp -o test_client_13_botanssl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3 -static' >> /start.sh && \
    echo 'g++ test_client_12_botanssl_key_export.cpp -o test_client_12_botanssl_key_export -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3 -static' >> /start.sh && \
    echo 'g++ test_client_13_botanssl_key_export.cpp -o test_client_13_botanssl_key_export -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3 -static' >> /start.sh && \
    echo 'cp test_client_12_botanssl test_client_13_botanssl test_client_12_botanssl_key_export test_client_13_botanssl_key_export /compiled_clients/' >> /start.sh && \
    
    # Build shared release
    echo 'make clean' >> /start.sh && \
    echo './configure.py --disable-static-library' >> /start.sh && \
    echo 'make all -j$(nproc)' >> /start.sh && \
    echo 'make install' >> /start.sh && \
    
    # Compile dynamic versions of the test clients
    echo 'g++ test_client_12_botanssl.cpp -o test_client_12_botanssl_dl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3' >> /start.sh && \
    echo 'g++ test_client_13_botanssl.cpp -o test_client_13_botanssl_dl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3' >> /start.sh && \
    echo 'g++ test_client_12_botanssl_key_export.cpp -o test_client_12_botanssl_key_export_dl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3' >> /start.sh && \
    echo 'g++ test_client_13_botanssl_key_export.cpp -o test_client_13_botanssl_key_export_dl -std=c++20 -I/usr/local/include/botan-3 -L/usr/local/lib -lbotan-3' >> /start.sh && \

    # Copy dynamic versions of test clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_botanssl_dl test_client_13_botanssl_dl test_client_12_botanssl_key_export_dl test_client_13_botanssl_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cp /usr/local/lib/*.so* /compiled_clients/libs/' >> /start.sh && \
    
    # Save version information
    echo 'echo "TLS Library: BotanSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \
    
    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]