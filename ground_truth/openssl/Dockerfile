# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin

#Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    cmake \
    python3 \
    && apt-get clean

#Increase the Git Buffer Size
RUN git config --global http.postBuffer 104857600

# Clone the OpenSSL repository
RUN git clone https://github.com/openssl/openssl.git || \
    (sleep 5 && git clone https://github.com/openssl/openssl.git) || \
    (sleep 10 && git clone https://github.com/openssl/openssl.git)

# Set the working directory to openssl
WORKDIR /openssl

# Copy the test client source files into the container
COPY test_client_12_openssl.c /openssl/
COPY test_client_12_openssl_key_export.c /openssl/
COPY test_client_13_openssl.c /openssl/
COPY test_client_13_openssl_key_export.c /openssl/
COPY test_client_13_openssl_debug.c /openssl/

# Dynamically set the version during the build to the latest version at build time
RUN export VERSION=$(git describe --tags --always) && \
    echo "Setting the version: $VERSION" && \
    echo "VERSION=$VERSION" >> /etc/environment

# Create a startup script to handle "pinned" and "latest" versions
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'source /etc/environment' >> /start.sh && \
    echo 'if [ "$1" == "latest" ]; then' >> /start.sh && \
    echo '    echo "Building latest version of OpenSSL...";' >> /start.sh && \
    echo '    git pull;' >> /start.sh && \
    echo 'else' >> /start.sh && \
    echo '    echo "Checking out pinned version: $VERSION";' >> /start.sh && \
    echo '    git checkout $VERSION;' >> /start.sh && \
    echo 'fi' >> /start.sh && \
    echo './config && make;' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_openssl test_client_12_openssl.c libssl.a libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_openssl_key_export test_client_12_openssl_key_export.c libssl.a libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl test_client_13_openssl.c libssl.a libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl_debug test_client_13_openssl_debug.c libssl.a libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl_key_export test_client_13_openssl_key_export.c libssl.a libcrypto.a -lpthread -ldl -static' >> /start.sh && \
    echo 'cp test_client_12_openssl test_client_12_openssl_key_export test_client_13_openssl test_client_13_openssl_debug test_client_13_openssl_key_export /compiled_clients/' >> /start.sh && \
    # Compile shared versions
    echo 'make clean' >> /start.sh && \
    echo './config shared' >> /start.sh && \
    echo 'make -j $(nproc)' >> /start.sh && \
    echo 'make install' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_openssl_dl test_client_12_openssl.c -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_12_openssl_key_export_dl test_client_12_openssl_key_export.c -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl_dl test_client_13_openssl.c -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl_debug_dl test_client_13_openssl_debug.c -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    echo 'g++ -Iinclude -Ibuild/include -o test_client_13_openssl_key_export_dl test_client_13_openssl_key_export.c -lssl -lcrypto -lpthread -ldl' >> /start.sh && \
    # Copy all binaries to the compiled_clients directory
    echo 'cp test_client_12_openssl_dl test_client_12_openssl_key_export_dl test_client_13_openssl_dl test_client_13_openssl_debug_dl test_client_13_openssl_key_export_dl \
   /compiled_clients/' >> /start.sh && \
    echo 'mkdir -p /compiled_clients/libs/' >> /start.sh && \
    echo 'find . -name \*.so -exec cp {} /compiled_clients/libs/ \;' >> /start.sh && \
    echo 'echo "TLS Library: OpenSSL" > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo "Version: $VERSION" >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh
    
# Set CMD to execute the /start.sh script with arguments (defaults to using the pinned version)
CMD ["/start.sh"]
#CMD ["/bin/bash"]
