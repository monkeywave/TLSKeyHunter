#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

int main() {
    const char* host = "127.0.0.1";
    const int port = 4432;
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    SSL_SESSION* session = NULL;
    int sockfd = -1;
    int ret = -1;

    unsigned char client_random[32];
    size_t client_random_len = 32;
    unsigned char secret[48];
    size_t secret_len = 48;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Create a new SSL context
    ctx = SSL_CTX_new(TLS_client_method());
    if(ctx == NULL){
        printf("SSL_CTX_new failed\n");
        goto exit;
    }

    // Restrict version to TLS 1.2
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);

    // Create a new SSL structure
    ssl = SSL_new(ctx);
    if (ssl == NULL){
        printf("SSL_new failed\n");
        goto exit;
    }

    // Create a socket and connect to the server
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0){
        printf("socket failed\n");
        goto exit;
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    if(inet_pton(AF_INET, host, &server_addr.sin_addr) <= 0){
        printf("inet_pton failed\n");
        goto exit;
    }

    if(connect(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0){
        printf("TCP connect failed\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Associate the socket with the SSL structure
    SSL_set_fd(ssl, sockfd);

    // Perform the TLS handshake
    if(SSL_connect(ssl) <= 0){
        printf("SSL_connect failed\n");
        goto exit;
    }
    
    // Print client random and master secret
    SSL_get_client_random(ssl, client_random, client_random_len);
    for(int i = 0; i < client_random_len; i++){
        printf("%02x", client_random[i]);
    }
    printf(" ");
    session = SSL_get_session(ssl);
    SSL_SESSION_get_master_key(session, secret, secret_len);
    for(int i = 0; i < secret_len; i++){
        printf("%02x", secret[i]);
    }
    printf("\n");
    
    // Keep connection open by waiting for user input
    printf("Connected to %s:%d. Press Enter to disconnect...\n", host, port);
    getchar();

    ret = 0;


exit:
    // Clean up
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    EVP_cleanup();

    return ret;
}