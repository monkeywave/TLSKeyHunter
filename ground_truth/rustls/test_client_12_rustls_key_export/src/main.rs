// based on: https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleclient.rs
use std::sync::Arc;
use std::net::TcpStream;
use std::io::Write;
use rustls::{ClientConfig, ClientConnection, Stream, Error, DigitallySignedStruct, SignatureScheme, KeyLog, 
    client::danger::{
                    ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid
    }
};
use rustls::pki_types::{ServerName, IpAddr, CertificateDer, UnixTime};

// Custom verifier to accept any server certificate
#[derive(Debug)]struct MyVerifier;

impl ServerCertVerifier for MyVerifier {
    fn verify_server_cert(&self, _end_entity: &CertificateDer, _intermediates: &[CertificateDer], _server_name: &ServerName<'_>, _ocsp_response: &[u8], _now: UnixTime) -> Result<ServerCertVerified, Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error>{
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(&self, _message: &[u8], _cert: &CertificateDer<'_>, _dss: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, Error>{
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        // Some of the supported signature schemes (should be enough for this application's purpose)
        vec![
        SignatureScheme::RSA_PKCS1_SHA256,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP521_SHA512,
        SignatureScheme::ED25519,
        SignatureScheme::ED448]
    }
}

#[derive(Debug)] struct LogToConsole;

// Log the given key material to the console
impl KeyLog for LogToConsole{
    fn log(&self, label: &str, client_random: &[u8], secret: &[u8]){
        let client_random_hex = hex::encode(client_random);
        let secret_hex = hex::encode(secret);
        println!("{} {} {}", label, client_random_hex, secret_hex);
    }
}


fn main() {
    // Waiting for user to start the Connection
    println!("Press enter to proceed...");
    std::io::stdin().read_line(&mut String::new()).unwrap();

    // Using the "dangerous" API to set a custom certificate verifier
    // Restrict the protocol versions to TLS 1.2
    let mut config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MyVerifier))
        .with_no_client_auth();
    
    // Enable key extraction an set our function
    config.enable_secret_extraction = true;
    config.key_log = Arc::new(LogToConsole);

    let ip = "127.0.0.1";
    let ip_with_port = "127.0.0.1:4432";
    let server_name = ServerName::IpAddress(IpAddr::try_from(ip).unwrap());

    // Establish a TCP connection to the server
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(ip_with_port).unwrap();
    println!("TCP connected");

    let mut tls = Stream::new(&mut conn, &mut sock);
    // send some data to trigger the TLS handshake
    tls.write("test".as_bytes()).unwrap();

    println!("TLS Connected to: {:?}", ip_with_port);
    println!("Press enter to disconnect");
    std::io::stdin().read_line(&mut String::new()).unwrap();
    
}