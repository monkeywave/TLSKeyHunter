#define SSL_LIBRARY_VERSION_TLS_1_2 0x0303

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <nss/nss.h>
#include <nss/ssl.h>
#include <prnetdb.h>
#include <prio.h>
#include <prerror.h>
#include <nspr.h>

SECStatus acceptAllCerts(void* arg, PRFileDesc* fd, PRBool checksig, PRBool isServer){
    return SECSuccess;
}

int main(){
    const char* hostname = "127.0.0.1";
    const char* port = "4432";
    struct addrinfo *res, hints = {};
    int ret = -1;
    PRFileDesc* nss_socket = NULL;
    PRFileDesc* tcp_sock = NULL;

    SSLVersionRange version_range;
    version_range.min = SSL_LIBRARY_VERSION_TLS_1_2;
    version_range.max = SSL_LIBRARY_VERSION_TLS_1_2;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Initialize NSS
    if (NSS_NoDB_Init(NULL) != SECSuccess) {
        fprintf(stderr, "NSS initialization failed.\n");
        return 1;
    }

    // Initialize NSPR
    PR_Init(PR_SYSTEM_THREAD, PR_PRIORITY_NORMAL, 0);

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);

    // Create and connect socket using NSPR
    tcp_sock = PR_OpenTCPSocket(res->ai_family);
    if (tcp_sock == NULL) {
        printf("Unable to create TCP socket\n");
        goto exit;
    }

    // TCP Connect to Server
    PRNetAddr addr;
    PR_InitializeNetAddr(PR_IpAddrNull, 0, &addr);
    PR_StringToNetAddr(hostname, &addr);
    addr.inet.port = PR_htons(atoi(port));

    if (PR_Connect(tcp_sock, &addr, PR_INTERVAL_NO_TIMEOUT) != PR_SUCCESS) {
        printf("Unable to TCP connect to server\n");
        goto exit;
    } else {
        printf("Established TCP connection\n");
    }

    // Import the socket into NSS
    nss_socket = SSL_ImportFD(NULL, tcp_sock);
    if (nss_socket == NULL) {
        printf("Unable to import TCP socket to NSS\n");
        goto exit;
    }

    // Restrict TLS version to 1.2
    if (SSL_VersionRangeSet(nss_socket, &version_range) != SECSuccess) {
        printf("Unable to set TLS version range");
        goto exit;
    }

    // Set our own certificate verification function to accept the servers Certificate
    if (SSL_AuthCertificateHook(nss_socket, acceptAllCerts, NULL) != SECSuccess) {
        printf("Unable to set certificate verification function\n");
        goto exit;
    }
    
    // Reset Handshake
    if (SSL_ResetHandshake(nss_socket, 0) != SECSuccess) {
        printf("Unable to reset handshake\n");
        goto exit;
    }

    // Perform Handshake
    if(SSL_ForceHandshake(nss_socket) != SECSuccess){
        printf("Unable to force handshake\n");
        printf("Error message: %s\n", PR_ErrorToString(PR_GetError(), 0));
        goto exit;
    }

    printf("Established TLS connection\n");

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;

exit:
    // Close connection and close socket
    if (nss_socket != NULL) {
        PR_Close(nss_socket);
    }
    if (res != NULL) {
        freeaddrinfo(res);
    }
    SSL_ClearSessionCache();
    NSS_Shutdown();
    PR_Cleanup();
    return ret;
}