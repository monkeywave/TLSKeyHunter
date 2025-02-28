#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

int main(){
    const char* hostname = "127.0.0.1";
    const char* port = "4433";
    struct addrinfo *res, hints = {};
    int ret = -1;
    int sock = -1;
    gnutls_session_t session;
    const char *err;
    int err_code = 0;
    gnutls_certificate_credentials_t xcred;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);


    // Initialize GnuTLS
    gnutls_global_init();
    printf("DEBUG: gnutls_global_init() \n");

    // Initialize session
    if(gnutls_init(&session, GNUTLS_CLIENT) != 0){
        printf("DEBUG: gnutls_init() \n");
        printf("Error initializing session");
        goto exit;
    }
    printf("DEBUG: gnutls_init() \n");

    gnutls_certificate_allocate_credentials(&xcred);
    printf("DEBUG: gnutls_certificate_allocate_credentials() \n");
    gnutls_certificate_set_x509_system_trust(xcred);
    printf("DEBUG: gnutls_certificate_set_x509_system_trust() \n");

    // Set priority and restrict to TLS 1.3
    if (gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", &err) != 0) {
        printf("DEBUG: gnutls_priotity_set_direct() \n");
        printf("Error setting priority \n");
        printf("Error: %s\n", err);
        goto exit;
    }
    printf("DEBUG: gnutls_priotity_set_direct() \n");
    
     // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server \n");
        goto exit;
    }else{
        printf("Established TCP connection \n");
    }

    // Set socket descriptor and Timeout
    gnutls_transport_set_int(session, sock);
    printf("DEBUG: gnutls_transport_set_int() \n");
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
    printf("DEBUG: gnutls_handshake_set_timeout() \n");

    // Set credentials
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);
    printf("DEBUG: gnutls_credentials_set() \n");

    // Perform Hanshake
    err_code = gnutls_handshake(session);
    printf("DEBUG: gnutls_handshake() \n");
    if(err_code < 0){
        printf("Error during handshake");
        printf("Error: %s\n", gnutls_strerror(err_code));
        goto exit;
    }

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;

exit:
    gnutls_deinit(session);
    printf("DEBUG: gnutls_deinit() \n");
    gnutls_global_deinit();
    printf("DEBUG: gnutls_global_deinit() \n");
    close(sock);
    return ret;
}

