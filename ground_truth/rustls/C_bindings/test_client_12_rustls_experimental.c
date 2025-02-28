#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <rustls.h>

// Custom verifier to accept any server certificate
rustls_result custom_verify_server_cert(
    void *userdata,
    const struct rustls_verify_server_cert_params *params
) {
    (void)userdata;
    (void)params;
    printf("Verified Certificate \n");
    return RUSTLS_RESULT_OK;
}

rustls_io_result write_callback(
    void *userdata,
    const uint8_t *buf,
    size_t count,
    size_t *out_n
) {
    int sockfd = *(int *)userdata;
    ssize_t result = write(sockfd, buf, count);
    if (result < 0) {
        return result; // Return the errno value as required by rustls_write_callback
    }
    *out_n = (size_t)result;
    printf("Wrote %ld bytes \n", *out_n);
    return 0; // Success
}

rustls_io_result read_callback(
    void *userdata,
    uint8_t *buf,
    size_t count,
    size_t *out_n
) {
    int sockfd = *(int *)userdata;
    ssize_t result = read(sockfd, buf, count);
    if (result < 0) {
        return result; // Return the errno value as required by rustls_read_callback
    }
    *out_n = (size_t)result;
    printf("Read %ld bytes \n", *out_n);
    return 0; // Success
}


int main() {
    const char* hostname = "127.0.0.1";
    const char* port = "4432";
    struct addrinfo *res, hints ={};
    int sock = -1;

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    // Resolve hostname
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    getaddrinfo(hostname, port, &hints, &res);


    // Create and connect socket
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (connect(sock, res->ai_addr, res->ai_addrlen) != 0) {
        printf("Unable to TCP connect to server\n");
        return -1;
    }else{
        printf("Established TCP connection\n");
    }

    // Create a TLS client config with custom verifier
    struct rustls_client_config_builder *config_builder = rustls_client_config_builder_new();

    if (!config_builder) {
        fprintf(stderr, "Failed to create rustls client config builder\n");
        return -1;
    }

    // Set custom certificate verifier
    rustls_client_config_builder_dangerous_set_certificate_verifier(
        config_builder,
        custom_verify_server_cert
    );


    // Build the client configuration
    const struct rustls_client_config *config = NULL;
    if (rustls_client_config_builder_build(config_builder, &config) != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to build rustls client config\n");
        return -1;
    }

    struct rustls_connection *conn;
    if (rustls_client_connection_new(config, hostname, &conn) != RUSTLS_RESULT_OK) {
        fprintf(stderr, "Failed to create rustls connection\n");
        close(sock);
        return -1;
    }
    
    // Perform the handshake
    while (rustls_connection_is_handshaking(conn)) {
        if (rustls_connection_wants_write(conn)) {
            size_t out_n = 0;
            if (rustls_connection_write_tls(conn, write_callback, &sock, &out_n) != 0) {
                fprintf(stderr, "TLS write failed\n");
                break;
            }
        }
        if (rustls_connection_wants_read(conn)) {
            size_t out_n = 0;
            
            if (rustls_connection_read_tls(conn, read_callback, &sock, &out_n) != 0) {
                fprintf(stderr, "TLS read failed\n");
                break;
            }
            if (rustls_connection_process_new_packets(conn) != RUSTLS_RESULT_OK) {
                fprintf(stderr, "rustls_connection_process_new_packets failed");
                break;
            }
        }
    }

    if (rustls_connection_is_handshaking(conn)) {
        fprintf(stderr, "TLS handshake failed to complete\n");
        rustls_connection_free(conn);
        close(sock);
        return -1;
    }

    printf("TLS Connected to: %s:%s\n", hostname, port);
    printf("Press enter to disconnect\n");
    getchar();

    rustls_connection_free(conn);
    rustls_client_config_free(config);
    close(sock);
    return 0;
}
