/*
compilation: 
g++ -Iinclude -Ibuild/include -o test_client_12_boringssl test_client_12_boringssl.c build/ssl/libssl.a build/crypto/libcrypto.a -lpthread -ldl

based on https://github.com/openssl/openssl/blob/master/demos/sslecho/main.c
*/

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <stdio.h>

int main() {
    const char* hostname = "127.0.0.1";
    const char* port = "4432";                
    struct addrinfo *res, hints = {};
    int sock = -1;
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    int ret = 1;  // Default to failure

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Define ssl method and create context
    const SSL_METHOD *method = TLSv1_2_client_method();
    ctx = SSL_CTX_new(method);

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);


    // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Link SSL to socket and do handshake
    ssl = SSL_new(ctx);
    if (!ssl) {
        printf("Error creating SSL object\n");
        goto exit;
    }

    SSL_set_fd(ssl, sock);
    if (SSL_connect(ssl) != 1) {
        printf("Unable to SSL connect to server\n");
        goto exit;
    }else{
        printf("Established TLS connection\n");
    }

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;

    
exit:
    // Close connection, clear ssl object and close socket
    if (ssl != NULL) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    close(sock);
    return ret;
}
