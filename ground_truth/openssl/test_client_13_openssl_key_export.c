#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <stdio.h>

// prints the keylog
void printKeylogCb(const SSL *ssl, const char *line) {
    printf("%s\n", line);
}

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
    ctx = SSL_CTX_new(method);

    // Restrict version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    // Set keylog callback function
    SSL_CTX_set_keylog_callback(ctx, printKeylogCb);

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
    if(!ssl){
        printf("Error creating SSL object\n");
        goto exit;
    }

    SSL_set_fd(ssl, sock);
    if(SSL_connect(ssl) != 1){
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
    if(ssl != NULL){
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    SSL_CTX_free(ctx);
    close(sock);
    return ret;

}