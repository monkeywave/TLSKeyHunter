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
    libc6-dbg \
    libunwind-dev \
    pkg-config \
    python3 \
    && apt-get clean

# Clone the BoringSSL repository
RUN git clone https://boringssl.googlesource.com/boringssl

# Set the working directory to boringssl
WORKDIR /boringssl


# Copy the test client source files into the container
COPY test_client_12_boringssl.c /boringssl/
COPY test_client_12_boringssl_key_export.c /boringssl/
COPY test_client_13_boringssl.c /boringssl/
COPY test_client_13_boringssl_key_export.c /boringssl/


# Dynamically set the pinned commit hash during the build to the latest version at build time
RUN export PINNED_COMMIT_HASH=$(git rev-parse HEAD) && \
    echo "Pinning the commit: $PINNED_COMMIT_HASH" && \
    echo "PINNED_COMMIT_HASH=$PINNED_COMMIT_HASH" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of BoringSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $PINNED_COMMIT_HASH";' >> /start.sh && \
    echo '    git checkout $PINNED_COMMIT_HASH;' >> /start.sh && \
    echo 'fi' >> /start.sh && \

    # Build standard release version (static)
    echo 'echo "Building standard release version (static)..."' >> /start.sh && \
    echo 'mkdir -p build && cd build && cmake .. && make;' >> /start.sh && \
    echo 'cd ..' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_boringssl test_client_12_boringssl.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_boringssl_key_export test_client_12_boringssl_key_export.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_boringssl test_client_13_boringssl.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_boringssl_key_export test_client_13_boringssl_key_export.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'cp test_client_12_boringssl test_client_12_boringssl_key_export test_client_13_boringssl test_client_13_boringssl_key_export /compiled_clients/' >> /start.sh && \

    # Build debug version (static)
    echo 'echo "Building debug version (static)..."' >> /start.sh && \
    echo 'mkdir -p build_debug_static && cd build_debug_static && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" -DBUILD_SHARED_LIBS=OFF -DDEBUG=1 && make;' >> /start.sh && \
    echo 'cd ..' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild_debug_static/include -o test_client_13_boringssl_key_export_debug_version test_client_13_boringssl_key_export.c build_debug_static/ssl/libssl.a build_debug_static/crypto/libcrypto.a -lpthread -ldl -lc -static-libgcc -Wl,--start-group -lc -lgcc -Wl,--end-group' >> /start.sh && \
    echo 'cp test_client_13_boringssl_key_export_debug_version /compiled_clients/' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild_debug_static/include -o test_client_12_boringssl_key_export_debug_version test_client_12_boringssl_key_export.c build_debug_static/ssl/libssl.a build_debug_static/crypto/libcrypto.a -lpthread -ldl -lc -static-libgcc -Wl,--start-group -lc -lgcc -Wl,--end-group' >> /start.sh && \

    # Build debug version (shared)
    echo 'echo "Building debug version (shared)..."' >> /start.sh && \
    echo 'mkdir -p build_debug_shared && cd build_debug_shared && cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0" -DCMAKE_CXX_FLAGS="-g -O0" -DBUILD_SHARED_LIBS=ON -DDEBUG=1 && make;' >> /start.sh && \
    echo 'cd ..' >> /start.sh && \
    echo 'g++ -g -Iinclude -Ibuild_debug_shared/include -o test_client_13_boringssl_key_export_debug_version_dl test_client_13_boringssl_key_export.c -Lbuild_debug_shared/ssl -Lbuild_debug_shared/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'cp test_client_13_boringssl_key_export_debug_version_dl /compiled_clients/' >> /start.sh && \
    echo 'g++ -g -Iinclude -Ibuild_debug_shared/include -o test_client_12_boringssl_key_export_debug_version_dl test_client_12_boringssl_key_export.c -Lbuild_debug_shared/ssl -Lbuild_debug_shared/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \

    # Build shared release version
    echo 'echo "Building shared release version..."' >> /start.sh && \
    echo 'cd build && make clean && cmake -DBUILD_SHARED_LIBS=ON .. && make;' >> /start.sh && \
    echo 'cd ..' >> /start.sh && \

    # Compile dynamic versions of test clients
    echo 'export LD_LIBRARY_PATH=./build/ssl:./build/crypto:$LD_LIBRARY_PATH' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_boringssl_dl test_client_12_boringssl.c -Lbuild/ssl -Lbuild/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_boringssl_key_export_dl test_client_12_boringssl_key_export.c -Lbuild/ssl -Lbuild/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_boringssl_dl test_client_13_boringssl.c -Lbuild/ssl -Lbuild/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_boringssl_key_export_dl test_client_13_boringssl_key_export.c -Lbuild/ssl -Lbuild/crypto -lssl -lcrypto -lpthread -ldl' >> /start.sh && \

    # Copy dynamic versions of test clients and shared libraries
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'cp test_client_12_boringssl_dl test_client_12_boringssl_key_export_dl test_client_13_boringssl_dl test_client_13_boringssl_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'find . -name \*.so -exec cp {} /compiled_clients/libs/ \;' >> /start.sh && \

    # Save version information
    echo 'git log -1 --format="%H %cd" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "TLS Library: BoringSSL" >> /compiled_clients/version.md' >> /start.sh && \

    chmod +x /start.sh

# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]
