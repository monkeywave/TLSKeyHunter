// Enable Keylogging
#define WOLFSSL_SSLKEYLOGFILE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

void print_file_content(const char* filename){
    FILE* file = fopen(filename, "r");
    if(file == NULL){
        printf("Unable to open file %s\n", filename);
        return;
    }

    char buffer[1024];
    while(fgets(buffer, sizeof(buffer), file) != NULL){
        printf("%s", buffer);
    }

    printf("\n");
    fclose(file);
}

int main(){
    const char* hostname = "127.0.0.1";
    const char* port = "4433";
    struct addrinfo* res, hints = {};
    int sock = -1;
    int ret = -1;
    WOLFSSL_CTX* ctx;
    WOLFSSL* ssl;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Remove KeyLogFile from previous run
    remove("sslkeylog.log");

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

    // Initialize wolfSSL
    wolfSSL_Init();

    // Create Context
    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if(ctx == NULL){
        printf("Error creating context");
        goto exit;
    }

    // Set the verification mode to none
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, NULL);

    // Create SSL object
    ssl = wolfSSL_new(ctx);
    if(ssl == NULL){
        printf("Error creating SSL Object");
        goto exit;
    }

    // Set socket
    wolfSSL_set_fd(ssl, sock);

    // Establish TLS-Connection
    if(wolfSSL_connect(ssl) != SSL_SUCCESS){
        printf("Unable to SSL connect to server \n");    
        goto exit;
    }else{
        printf("Established TLS Connection");
    }

    // Logging Keys to console
    print_file_content("sslkeylog.log");

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;


exit:
    // Cleanup
    if(ctx != NULL){
        wolfSSL_CTX_free(ctx);
    }
    wolfSSL_Cleanup();

    return ret;
}