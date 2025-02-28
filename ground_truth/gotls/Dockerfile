# Use the official Ubuntu base image
FROM ubuntu:latest

# Set environment variables to avoid interactive prompts during the build
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Berlin


# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    wget \
    build-essential \
    && apt-get clean

# Install Go
RUN wget https://go.dev/dl/go1.23.2.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.2.linux-amd64.tar.gz && \
    rm go1.23.2.linux-amd64.tar.gz

# Set up Go Environment
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/go
ENV PATH=$PATH:$GOPATH/bin

# Set the pinned Version
ENV PINNED_VERSION="go version go1.23.2 linux/amd64"

# Set Working Directory to gotls
WORKDIR /gotls

# Copy the test client source files into the container
COPY test_client_12_gotls/ /gotls/test_client_12_gotls/
COPY test_client_13_gotls/ /gotls/test_client_13_gotls/
COPY test_client_12_gotls_key_export/ /gotls/test_client_12_gotls_key_export/
COPY test_client_13_gotls_key_export/ /gotls/test_client_13_gotls_key_export/

# This startup script will build the test clients
# The static and dynamic clients are copied to /compiled_clients
RUN echo '#!/bin/bash\n' > /start.sh && \
    echo 'cd ./test_client_12_gotls' >> /start.sh && \
    echo 'CGO_ENABLED=0 go build -o test_client_12_gotls' >> /start.sh && \
    echo 'CGO_ENABLED=1 go build -o test_client_12_gotls_dl' >> /start.sh && \
    echo 'cp test_client_12_gotls test_client_12_gotls_dl /compiled_clients/' >> /start.sh && \
    echo 'cd ../test_client_13_gotls' >> /start.sh && \
    echo 'CGO_ENABLED=0 go build -o test_client_13_gotls' >> /start.sh && \
    echo 'CGO_ENABLED=1 go build -o test_client_13_gotls_dl' >> /start.sh && \
    echo 'cp test_client_13_gotls test_client_13_gotls_dl /compiled_clients/' >> /start.sh && \
    echo 'cd ../test_client_12_gotls_key_export' >> /start.sh && \
    echo 'CGO_ENABLED=0 go build -o test_client_12_gotls_key_export' >> /start.sh && \
    echo 'CGO_ENABLED=1 go build -o test_client_12_gotls_key_export_dl' >> /start.sh && \
    echo 'cp test_client_12_gotls_key_export test_client_12_gotls_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'cd ../test_client_13_gotls_key_export' >> /start.sh && \
    echo 'CGO_ENABLED=0 go build -o test_client_13_gotls_key_export' >> /start.sh && \
    echo 'CGO_ENABLED=1 go build -o test_client_13_gotls_key_export_dl' >> /start.sh && \
    echo 'cp test_client_13_gotls_key_export test_client_13_gotls_key_export_dl /compiled_clients/' >> /start.sh && \
    echo 'echo $PINNED_VERSION > /compiled_clients/version.md' >> /start.sh && \
    echo 'echo TLS Library: GoTLS >> /compiled_clients/version.md' >> /start.sh && \
    chmod +x /start.sh

CMD ["/start.sh"]
