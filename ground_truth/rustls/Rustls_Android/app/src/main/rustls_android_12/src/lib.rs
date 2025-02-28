// based on: https://github.com/rustls/rustls/blob/main/examples/src/bin/simpleclient.rs
use std::sync::Arc;
use std::net::TcpStream;
use std::io::Write;
use rustls::{ClientConfig, ClientConnection, Stream, Error, DigitallySignedStruct, SignatureScheme,
    client::danger::{
                    ServerCertVerifier, ServerCertVerified, HandshakeSignatureValid
    }
};
use rustls::pki_types::{ServerName, IpAddr, CertificateDer, UnixTime};
use jni::JNIEnv;
use jni::objects::{JClass, JString, JObject};

#[macro_use]
extern crate log;

// Custom verifier to accept any server certificate
#[derive(Debug)] struct MyVerifier;

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

#[no_mangle]
pub extern "C" fn Java_com_example_rustls_1android_RustTls_runTlsClient12(env: JNIEnv, instance: JObject) -> jni::sys::jstring {
     android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(log::Level::Debug)
                .with_tag("rustls_android")
     );

     let result = do_rust_12();

     // Convert Rust String to JNI `jstring`
     match env.new_string(result) {
         Ok(jstr) => jstr.into_raw(), // Return the jstring if conversion succeeds
         Err(_) => std::ptr::null_mut(), // Return null pointer in case of error
     }
}


fn do_rust_12() -> String{
    // Using the "dangerous" API to set a custom certificate verifier
    // Restrict the protocol versions to TLS 1.2
    let config = ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(MyVerifier))
        .with_no_client_auth();

    let ip = "10.0.2.2";
    let ip_with_port = "10.0.2.2:4432";
    let server_name = ServerName::IpAddress(IpAddr::try_from(ip).unwrap());

    // Establish a TCP connection to the server
    let mut conn = ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut sock = TcpStream::connect(ip_with_port).unwrap();
    println!("TCP connected");

    let mut tls = Stream::new(&mut conn, &mut sock);
    // send some data to trigger the TLS handshake
    tls.write("test".as_bytes()).unwrap();

    println!("TLS Connected to: {:?}", ip_with_port);
    format!("TLS Connected to: {:?}", ip_with_port)
}