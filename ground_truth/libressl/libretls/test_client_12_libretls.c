#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#include <tls.h>

int main(){
    const char* hostname = "127.0.0.1";
    const char* port = "4432";
    int ret = -1;

    struct tls_config *config = NULL;
    struct tls *ctx = NULL;
    const char* err;
    
    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Initialize libretls
    tls_init();

    // Create config
    config = tls_config_new();
    if(config == NULL){
        printf("Error creating config\n");
        goto exit;
    }

    // Disable verification
    tls_config_insecure_noverifycert(config);
    tls_config_insecure_noverifyname(config);

    // Create Context
    ctx = tls_client();
    if(ctx == NULL){
        printf("Error creating TLS object\n");
        goto exit;
    }

    // Configure Context
    if(tls_configure(ctx, config) != 0){
        printf("Error configuring TLS object\n");
        goto exit;
    }

    // Restrict to TLS 1.2
    // Version is not set properly
    if(tls_config_set_protocols(config, TLS_PROTOCOL_TLSv1_2) != 0){
        printf("Error setting protocols\n");
        goto exit;
    }else{
        printf("Set TLS 1.2\n");
    }

    if(tls_connect(ctx, hostname, port) != 0){
        printf("Unable to TCP connect to server\n");
        goto exit;
    } else {
        printf("Established TCP connection\n");
    }

    if(tls_handshake(ctx) != 0){
        printf("Unable to SSL connect to server\n");
        err = tls_error(ctx);
        printf("Error: %s\n", err);
        goto exit;
    } else{
        printf("Established TLS connection\n");
    }

    // Keep connection open by waiting for user input
    printf("Connected to %s:%s. Press Enter to disconnect...\n", hostname, port);
    getchar();


    ret = 0;

exit:
    // Close connection and cleanup
    if( ctx != NULL){
        tls_close(ctx);
        tls_free(ctx);
    }
    if(config != NULL){
        tls_config_free(config);
    }
    
    return ret;
}