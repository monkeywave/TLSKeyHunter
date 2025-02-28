/*
// Examples from BotanSSL (outdated version)
https://botan.randombit.net/handbook/api_ref/tls.html#tls-client-example
https://github.com/randombit/botan/blob/master/src/cli/tls_client.cpp
*/

#include <botan/auto_rng.h>
#include <botan/certstor.h>
#include <botan/certstor_system.h>
#include <botan/tls.h>
#include <iostream>
#include <memory>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>

class Callbacks : public Botan::TLS::Callbacks{
public:
    Callbacks(int sockfd) : m_sockfd(sockfd) {}

    void tls_emit_data(std::span<const uint8_t> data) override{
        // send data to tls server, e.g., using BSD sockets or boost asio
        ::send(m_sockfd, data.data(), data.size(), 0);
    }

    void tls_record_received(uint64_t seq_no, std::span<const uint8_t> data) override{
        // process full TLS record received by tls server, e.g.,
        // by passing it to the application
        std::cout << "Received: " << std::string(reinterpret_cast<const char *>(data.data()), data.size()) << std::endl;
    }

    void tls_alert(Botan::TLS::Alert alert) override{
        // handle a tls alert received from the tls server
        std::cerr << "TLS Alert: " << alert.type_string() << std::endl;
    }

    // Override tls_verify_cert_chain to disable certificate verification
    void tls_verify_cert_chain(const std::vector<Botan::X509_Certificate> &cert_chain,
                               const std::vector<std::optional<Botan::OCSP::Response>> &ocsp_responses,
                               const std::vector<Botan::Certificate_Store *> &trusted_roots,
                               Botan::Usage_Type usage,
                               std::string_view hostname,
                               const Botan::TLS::Policy &policy) override{}

private:
    int m_sockfd;
};

class Client_Credentials : public Botan::Credentials_Manager{
public:
    std::vector<Botan::Certificate_Store *> trusted_certificate_authorities(const std::string &type,
                                                                            const std::string &context) override{
        BOTAN_UNUSED(type, context);
        // return a list of certificates of CAs we trust for tls server certificates
        // ownership of the pointers remains with Credentials_Manager
        return {};
    }

    std::vector<Botan::X509_Certificate> cert_chain(
        const std::vector<std::string> &cert_key_types,
        const std::vector<Botan::AlgorithmIdentifier> &cert_signature_schemes,
        const std::string &type,
        const std::string &context) override{
        BOTAN_UNUSED(cert_key_types, cert_signature_schemes, type, context);

        // when using tls client authentication (optional), return
        // a certificate chain being sent to the tls server,
        // else an empty list
        return {};
    }

    std::shared_ptr<Botan::Private_Key> private_key_for(const Botan::X509_Certificate &cert,
                                                        const std::string &type,
                                                        const std::string &context) override{
        BOTAN_UNUSED(cert, type, context);
        // when returning a chain in cert_chain(), return the private key
        // associated with the leaf certificate here
        return nullptr;
    }
};

// Policy to enforce TLS 1.3
class TLS13_Policy : public Botan::TLS::Policy {
public:
    bool acceptable_protocol_version(Botan::TLS::Protocol_Version version) const override {
        return (version == Botan::TLS::Protocol_Version::TLS_V13);
    }
};

int main(){
    // prepare all the parameters
    auto rng = std::make_shared<Botan::AutoSeeded_RNG>();
    auto session_mgr = std::make_shared<Botan::TLS::Session_Manager_In_Memory>(rng);
    auto creds = std::make_shared<Client_Credentials>();
    auto policy = std::make_shared<TLS13_Policy>();

    // create and connect the socket
    const char *hostname = "127.0.0.1";
    const char *port = "4433";

    // Wait for user to start
    printf("Starting client\n");
    printf("Press Enter to proceed...\n");
    getchar();

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, port, &hints, &res) != 0){
        std::cerr << "Error getting address info" << std::endl;
        return 1;
    }

    int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sockfd == -1){
        std::cerr << "Error creating socket" << std::endl;
        freeaddrinfo(res);
        return 1;
    }

    if (connect(sockfd, res->ai_addr, res->ai_addrlen) == -1){
        std::cerr << "Error connecting to server" << std::endl;
        close(sockfd);
        freeaddrinfo(res);
        return 1;
    }else{
        std::cout << "TCP Connected to server" << std::endl;
    }

    freeaddrinfo(res);

    auto callbacks = std::make_shared<Callbacks>(sockfd);

    // open the tls connection
    Botan::TLS::Client client(callbacks,
                              session_mgr,
                              creds,
                              policy,
                              rng,
                              Botan::TLS::Server_Information(hostname, port),
                              Botan::TLS::Protocol_Version::TLS_V13);

    while (!client.is_closed()){
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval timeout = {1, 0};
        ::select(sockfd + 1, &readfds, nullptr, nullptr, &timeout);

        if (FD_ISSET(sockfd, &readfds)){
            uint8_t buf[4096];
            ssize_t received = ::recv(sockfd, buf, sizeof(buf), 0);
            if (received <= 0)
            {
                break;
            }
            client.received_data(buf, received);
        }

        if (client.is_active()){
            // Keep connection open and terminate it on user input
            std::cout << "Connected to " << hostname << ":" << port << ". Press Enter to disconnect..." << std::endl;
            getchar();
            close(sockfd);
            return 0;
        }
    }

    close(sockfd);
    return 0;
}