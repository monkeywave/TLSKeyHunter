#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <gnutls/gnutls.h>

int printKeylogCb(gnutls_session_t session, const char* label, const gnutls_datum_t *secret) {
    gnutls_datum_t client_random, server_random;

   // Retrieve the client and server random values
   gnutls_session_get_random(session, &client_random, &server_random);
   
   // Check if the client_random data is valid
   if (client_random.size == 0 || client_random.data == NULL) {
	fprintf(stderr, "Failed to retrieve client random data.\n"); return -1;
   }

    printf("%s ", label);

    // Print the client random
    for (size_t i = 0; i < client_random.size; i++) {
        printf("%02x", client_random.data[i]);
    }

    printf(" ");

    // Print the secret
    for (size_t i = 0; i < secret->size; i++) {
        printf("%02x", secret->data[i]);
    }

    printf("\n");

    return 0;
}

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
    gnutls_datum_t master_secret = {NULL, 0};

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
    

    // Initialize session
    if(gnutls_init(&session, GNUTLS_CLIENT) != 0){
        printf("Error initializing session");
        goto exit;
    }

    gnutls_certificate_allocate_credentials(&xcred);
    gnutls_certificate_set_x509_system_trust(xcred);

    // Set priority and restrict to TLS 1.3
    if (gnutls_priority_set_direct(session, "NORMAL:-VERS-ALL:+VERS-TLS1.3", &err) != 0) {
        printf("Error setting priority\n");
        printf("Error: %s\n", err);
        goto exit;
    }
    
     // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    }else{
        printf("Established TCP connection\n");
    }

    // Set socket descriptor and Timeout
    gnutls_transport_set_int(session, sock);
    gnutls_handshake_set_timeout(session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);

    // Set credentials
    gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, xcred);

    // Set the KeyLog Callback (only exports client random)
    gnutls_session_set_keylog_function(session, printKeylogCb);

    // Perform Hanshake
    err_code = gnutls_handshake(session);
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
    gnutls_global_deinit();
    close(sock);
    return ret;
}

