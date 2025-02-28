#ifndef __BEGIN_HIDDEN_DECLS
#define __BEGIN_HIDDEN_DECLS
#endif

#ifndef __END_HIDDEN_DECLS
#define __END_HIDDEN_DECLS
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include "/portable/ssl/ssl_local.h"

// Print the Client Random and the label of the following secret
void printRandom(unsigned char *client_random, size_t client_random_len, const char* label){
    printf("%s ", label);
    for(int i = 0; i < client_random_len; i++){
        printf("%02x", client_random[i]);
    }
    printf(" ");
}

// Print the secrets
void logSecrets(unsigned char *client_random, size_t client_random_len, tls13_secrets *secrets){
    printRandom(client_random, client_random_len, "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
    for(int i = 0; i < secrets->client_handshake_traffic.len; i++){
        printf("%02x", secrets->client_handshake_traffic.data[i]);
    }
    printf("\n");

    printRandom(client_random, client_random_len, "SERVER_HANDSHAKE_TRAFFIC_SECRET");
    for(int i = 0; i < secrets->server_handshake_traffic.len; i++){
        printf("%02x", secrets->server_handshake_traffic.data[i]);
    }
    printf("\n");

    printRandom(client_random, client_random_len, "CLIENT_APPLICATION_TRAFFIC_SECRET");
    for(int i = 0; i < secrets->client_application_traffic.len; i++){
        printf("%02x", secrets->client_application_traffic.data[i]);
    }
    printf("\n");

    printRandom(client_random, client_random_len, "SERVER_APPLICATION_TRAFFIC_SECRET");
    for(int i = 0; i < secrets->server_application_traffic.len; i++){
        printf("%02x", secrets->server_application_traffic.data[i]);
    }
    printf("\n");

    printRandom(client_random, client_random_len, "EXPORTER_SECRET");
    for(int i = 0; i < secrets->exporter_master.len; i++){
        printf("%02x", secrets->exporter_master.data[i]);
    }
    printf("\n");

}

int main() {
    const char* host = "127.0.0.1";
    const int port = 4433;
    SSL* ssl = NULL;
    SSL_CTX* ctx = NULL;
    int sockfd = -1;
    int ret = -1;

    unsigned char client_random[32];
    size_t client_random_len = 32;
    tls13_secrets *secrets = NULL;

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

    // Restrict version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

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

    // Get the Client_Random and the secrets
    SSL_get_client_random(ssl, client_random, client_random_len);
    secrets = ssl->tls13->hs->tls13.secrets;
    // Print the secrets
    logSecrets(client_random, client_random_len, secrets);
    
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