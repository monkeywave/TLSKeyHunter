#!/bin/bash

start_server() {
    local tls_version=$1
    local port=$2
    echo "Starting OpenSSL server with $tls_version on port $port..."
    openssl s_server -$tls_version -cert /etc/ssl/certs/server.crt -key /etc/ssl/private/server.key -accept $port -www -naccept 100 &
}

# Check for the TLS version parameter
if [ "$1" == "tls1_2" ]; then
    echo "Starting OpenSSL server with TLS 1.2 support only..."
    openssl s_server -tls1_2 -cert /etc/ssl/certs/server.crt -key /etc/ssl/private/server.key -accept 44320 -www -naccept 100
elif [ "$1" == "tls1_3" ]; then
    echo "Starting OpenSSL server with TLS 1.3 support only..."
    openssl s_server -tls1_3 -cert /etc/ssl/certs/server.crt -key /etc/ssl/private/server.key -accept 4433 -www -naccept 100
else
    echo "Starting OpenSSL servers for both TLS 1.2 and TLS 1.3..."
    # Start TLS 1.2 on port 4432
    start_server "tls1_2" 4432
    # Start TLS 1.3 on port 4433
    start_server "tls1_3" 4433

    # Wait for both OpenSSL instances to exit
    wait
fi
