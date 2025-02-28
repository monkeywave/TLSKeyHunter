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
COPY test_client_12_libretls.c /portable/
COPY test_client_13_libretls.c /portable/

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
    echo './autogen.sh' >> /start.sh && \
    echo './configure --enable-static --disable-shared' >> /start.sh && \
    echo 'make install' >> /start.sh && \
    echo 'g++ test_client_12_libretls.c -o test_client_12_libretls -I/usr/local/include -L/usr/local/lib -ltls -lssl -lcrypto -static' >> /start.sh && \
    echo 'g++ test_client_13_libretls.c -o test_client_13_libretls -I/usr/local/include -L/usr/local/lib -ltls -lssl -lcrypto -static' >> /start.sh && \
    echo 'cp test_client_12_libretls test_client_13_libretls /compiled_clients/' >> /start.sh && \
    echo 'echo "TLS Library: LibreSSL (libretls)" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh


# Set CMD to execute the startup script
CMD ["/start.sh"]