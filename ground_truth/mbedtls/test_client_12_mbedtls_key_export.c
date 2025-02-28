#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <stdio.h>

// prints the keys according to the NSSkeylog format
void printKeylogCb(void *p_expkey, mbedtls_ssl_key_export_type type, 
                    const unsigned char *secret, size_t secret_len, 
                    const unsigned char client_random[32], 
                    const unsigned char server_random[32], mbedtls_tls_prf_types tls_prf_type){
                    
                        printf("CLIENT_RANDOM " );
                        for (size_t i = 0; i < 32; i++) {
                            printf("%02x", client_random[i]);
                        }
                        printf(" ");
                        for (size_t i = 0; i < secret_len; i++) {
                            printf("%02x", secret[i]);
                        }

                        printf("\n");
                    }

int main(){
    const char* hostname = "127.0.0.1";
    const char* port = "4432";
    struct addrinfo *res, hints = {};
    int sock = -1;
    int ret = -1;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // mbedtls contexts
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_net_context server_fd;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    // Initialize mbed TLS contexts
    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    // Seed the random number generator
    const char *pers = "ssl_client";
    if((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("Failed to seed random number generator\n");
        goto exit;
    }

    // Configure TLS settings
    if(mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT) != 0){
        printf("Error configuring SSL defaults\n");
        goto exit;
    }

    // Restrict version to TLS 1.2
    mbedtls_ssl_conf_min_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    mbedtls_ssl_conf_max_version(&conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
    

    // disable verification
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Set Key Callback
    mbedtls_ssl_set_export_keys_cb(&ssl, printKeylogCb, NULL);

    // Setup and connect
    if(mbedtls_ssl_setup(&ssl, &conf) != 0){
        printf("Error setting up SSL\n");
        goto exit;
    }

    if(mbedtls_net_connect(&server_fd, hostname, port, MBEDTLS_NET_PROTO_TCP) != 0){
        printf("Unable to TCP connect to server\n");
        goto exit;
    }

    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    // negotiate TLS
    if(mbedtls_ssl_handshake(&ssl) != 0){
        printf("Unable to SSL connect to server\n");
        goto exit;
    }

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();

    ret = 0;

exit:
    // Close the connection
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

