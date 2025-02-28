#include <s2n.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>

int  main() {
    const char* hostname = "127.0.0.1";
    const char* port = "4432";
    struct addrinfo *res, hints = {};
    int sock = -1;
    struct s2n_connection *conn = NULL;
    struct s2n_config *config = NULL;
    int ret = -1;  // Default to failure
    s2n_blocked_status blocked = S2N_NOT_BLOCKED;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Initialize s2n and create config
    if(s2n_init() != 0){
        printf("Error initializing s2n\n");
        goto exit;
    }
    config = s2n_config_new();

    // Configure version TLS 1.2
    if(s2n_config_set_cipher_preferences(config, "20170210") != 0){
        printf("Error setting cipher preferences\n");
        goto exit;
    }

    s2n_config_disable_x509_verification(config);

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

    // Create s2n connection and setting configuration
    conn = s2n_connection_new(S2N_CLIENT);
    if(s2n_connection_set_config(conn, config) != 0){
        printf("Error setting configuration\n");
        goto exit;
    }

    if(s2n_connection_set_fd(conn, sock)){
        printf("Error setting file descriptor\n");
        goto exit;
    }
    
    if(s2n_negotiate(conn, &blocked) != 0) {
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
    // Close connection and cleanup
    if(conn != NULL){
        s2n_shutdown(conn, NULL);
        s2n_connection_free(conn);
    }

    close(sock);
    s2n_cleanup();
    return ret;
}