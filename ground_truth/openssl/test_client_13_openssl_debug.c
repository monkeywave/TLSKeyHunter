#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <stdio.h>

int main(){
     const char* hostname = "127.0.0.1";
    const char* port = "4433";                
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
    const SSL_METHOD *method = TLS_client_method();
    printf("DEBUG: TLS_client_method() \n");
    ctx = SSL_CTX_new(method);
    printf("DEBUG: SSL_CTX_new() \n");

    //Restrict version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    printf("DEBUG: SSL_CTX_set_min_proto_version() \n");
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    printf("DEBUG: SSL_CTX_set_max_proto_version() \n");
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
    printf("DEBUG: SSL_new() \n");
    if(!ssl){
        printf("Error creating SSL object\n");
        goto exit;
    }

    SSL_set_fd(ssl, sock);
    printf("DEBUG: SSL_set_fd \n");
    if(SSL_connect(ssl) != 1){
        printf("DEBUG: SSL_connect() \n");
        printf("Unable to SSL connect to server\n");
        goto exit;
    }else{
        printf("DEBUG: SSL_connect() \n");
        printf("Established TLS connection\n");
    }

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;

exit:
    // Close connection, clear ssl object and close socket
    if(ssl != NULL){
        SSL_shutdown(ssl);
        printf("DEBUG: SSL_shutdown() \n");
        SSL_free(ssl);
        printf("DEBUG: SSL_free() \n");
    }
    SSL_CTX_free(ctx);
    printf("DEBUG: SSL_CTX_free() \n");
    close(sock);
    return ret;

}