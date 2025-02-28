// based on matrixssl-4-2-1-open/apps/ssl/simpleClient.c
#include "matrixssl/matrixsslApi.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>

// conifgs/fulltest/ enables, disables these
#define USE_DTLS
//#define USE_CERT_CHAIN_PARSING 
#define SSL_HS_RANDOM_SIZE 32


// Definition of sslRec struct
typedef struct {
    unsigned short len;
    unsigned char majVer;
    unsigned char minVer;
#ifdef USE_DTLS
    unsigned char epoch[2];
    unsigned char rsn[6];
#endif
#ifdef USE_CERT_CHAIN_PARSING
    unsigned short hsBytesHashed;
    unsigned short hsBytesParsed;
    unsigned short trueLen;
    unsigned char partial;
    unsigned char certPad;
#endif
    unsigned char type;
    unsigned char pad[3];
} sslRec;

// Definition of sslSec struct
typedef struct {
    unsigned char clientRandom[SSL_HS_RANDOM_SIZE];
    unsigned char serverRandom[SSL_HS_RANDOM_SIZE];
    unsigned char masterSecret[SSL_HS_MASTER_SIZE];
    // Other fields
} sslSec;

// Definition of ssl struct
typedef struct {
    sslRec rec;
    sslSec sec;
    // Other fields
} ssl;

// This accepts every certificate without 
static int32_t certCb(ssl_t *ssl, psX509Cert_t *cert, int32_t alert){
    return PS_SUCCESS;
}


// This function logs the master secret and the client random
int logMasterSecret(ssl_t* ssl, unsigned char* masterSecret, psSizeL_t* hsMasterSecretLen){
    // Calculate offset of sslSec struct
    sslSec* sec = (sslSec*)((unsigned char*)ssl + sizeof(sslRec));
    
    // Print the client random
    printf("CLIENT_RANDOM ");
    for(int i = 0; i < SSL_HS_RANDOM_SIZE; i++){
        printf("%02x", sec->clientRandom[i]);
    }
    printf(" ");
    
    // Print the master secret
    int rc = matrixSslGetMasterSecret(ssl, &masterSecret, hsMasterSecretLen);
    if (rc < 0){
        printf("matrixSslGetMasterSecret failed: %d\n", rc);
    }else{
        for(int i = 0; i < *hsMasterSecretLen; i++){
            printf("%02x", masterSecret[i]);
        }
        printf("\n");
    } 
    return rc;
}

int main(int argc, char **argv){
    uint16_t sigAlgs[] = {
        sigalg_ecdsa_secp256r1_sha256,
        sigalg_ecdsa_secp384r1_sha384,
        sigalg_ecdsa_secp521r1_sha512,
        sigalg_rsa_pss_rsae_sha256,
        sigalg_rsa_pss_rsae_sha384,
        sigalg_rsa_pkcs1_sha256
    };

    int32_t sigAlgsLen = sizeof(sigAlgs)/sizeof(sigAlgs[0]);
    psCipher16_t ciphersuites[] = {
        TLS_AES_128_GCM_SHA256,
        TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TLS_RSA_WITH_AES_128_GCM_SHA256
    };
    int32_t ciphersuitesLen = sizeof(ciphersuites)/sizeof(ciphersuites[0]);
    psProtocolVersion_t versions[] = {v_tls_1_2}; // Use TLS 1.2
    int32_t versionsLen = sizeof(versions)/sizeof(versions[0]);

    static const char* hostname = "127.0.0.1";
    const char* port = "4432";
    struct addrinfo *res, hints = {};
    sslSessOpts_t opts;
    sslKeys_t *keys = NULL;
    int32_t rc;
    uint32_t len;
    ssl_t *ssl = NULL;
    unsigned char *buf;
    ssize_t nrecv, nsent;
    int sock = -1;
    struct sockaddr_in addr;
    char* config = "YNYYYNNNNYYNY";

    // For logging the master secret
    unsigned char masterSecret[48];
    psSizeL_t hsMasterSecretLen = sizeof(masterSecret);

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    rc = matrixSslOpenWithConfig(config);
    if (rc < 0){
        return EXIT_FAILURE;
    }

    /* Allocate a new key structure.  */
    rc = matrixSslNewKeys(&keys, NULL);
    if (rc < 0){
        printf("matrixSslNewKeys failed: %d\n", rc);
        goto exit;
    }

    /* Load key material into 'keys'. The called function is a simple
       wrapper for matrixSslLoadKeysMem. */
    rc = matrixSslLoadRsaKeys(keys, NULL, NULL, NULL, NULL);
    if (rc < 0){
        printf("matrixSslLoadRsaKeys failed: %d\n", rc);
        goto exit;
    }

    /* Setup session options. */
    Memset(&opts, 0, sizeof(opts)); /* Important. */

    /* Set supported protocol versions. */
    rc = matrixSslSessOptsSetClientTlsVersions(&opts, versions, versionsLen);
    if (rc < 0){
        printf("matrixSslSessOptsSetClientTlsVersions failed: %d\n", rc);
        goto exit;
    }

    /* Set supported signature algorithms. */
    rc = matrixSslSessOptsSetSigAlgs(&opts, sigAlgs, sigAlgsLen);
    if (rc < 0){
        printf("matrixSslSessOptsSetSigAlgs failed: %d\n", rc);
        goto exit;
    }

    /* Create a new session and the ClientHello message. */
    rc = matrixSslNewClientSession(
            &ssl,
            keys,
            NULL,
            ciphersuites,
            ciphersuitesLen,
            certCb,
            NULL,
            NULL,
            NULL,
            &opts);
    if (rc < 0){
        printf("matrixSslNewClientSession failed: %d\n", rc);
        goto exit;
    }

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);

    // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0){
        printf("Unable to TCP connect to server\n");
        goto exit;
    } else {
        printf("Established TCP connection\n");
    }

WRITE_MORE:
    /* Get pointer to the output data to send. */
    rc = matrixSslGetOutdata(ssl, &buf);
    while (rc > 0){
        len = rc;

        /* Send it over the wire. */
        nsent = send(sock, buf, len, 0);
        if (nsent <= 0){
            printf("send() failed\n");
            goto exit;
        }

        /* Inform the TLS library how much we managed to send.
           Return code will tell us of what to do next. */
        rc = matrixSslSentData(ssl, nsent);
        if (rc < 0){
            printf("matrixSslSentData failed: %d\n", rc);
            goto exit;
        }else if (rc == MATRIXSSL_REQUEST_CLOSE){
            printf("Closing connection\n");
            goto exit;
        }else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE){
            // Log the master secret
            logMasterSecret(ssl, masterSecret, &hsMasterSecretLen);
            // Keep connection open by waiting for user input
            printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
            getchar();
            goto exit;
        }

        /* More data to send? */
        rc = matrixSslGetOutdata(ssl, &buf);
    }

READ_MORE:
    /* Get pointer to buffer where incoming data should be read into. */
    rc = matrixSslGetReadbuf(ssl, &buf);
    if (rc < 0){
        goto exit;
    }
    len = rc;

    /* Read data from the wire. */
    nrecv = recv(sock, buf, len, 0);
    if (nrecv < 0){
        goto exit;
    }

    /* Ask the TLS library to process the data we read.
       Return code will tell us what to do next. */
    rc = matrixSslReceivedData(ssl, nrecv, &buf, &len);
    if (rc < 0){
        goto exit;
    }else if (rc == MATRIXSSL_HANDSHAKE_COMPLETE){
            // Log the master secret
            logMasterSecret(ssl, masterSecret, &hsMasterSecretLen);
            // Keep connection open by waiting for user input
            printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
            getchar();
        goto exit;
    }else if (rc == MATRIXSSL_REQUEST_SEND){
        /* Handshake messages or an alert have been encoded.
           These need to be sent over the wire. */
        goto WRITE_MORE;
    }else if (rc == MATRIXSSL_REQUEST_RECV){
        /* Handshake still in progress. Need more messages
           from the peer. */
        goto READ_MORE;
    }else if (rc == MATRIXSSL_APP_DATA){
        /* Inform the TLS library that we "processed" the data. */
        rc = matrixSslProcessedData(ssl, &buf, &len);
        if (rc < 0)
        {
            goto exit;
        }
        /* This test ends after successful reception of encrypted
           app data from the peer. */
        goto exit;
    }

exit:
    // Cleanup
    if(keys != NULL){
        matrixSslDeleteKeys(keys);
    }
    if(sock != -1){
        close(sock);
    }
    if(ssl != NULL){
        matrixSslDeleteSession(ssl);
    }
    psCoreClose();
    matrixSslClose();
    return rc; 
}