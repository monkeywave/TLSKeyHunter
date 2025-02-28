package com.example.test_client_12_bouncycastle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestClient12BouncyCastle {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 4432;

    public static void main(String[] args){
        // Add the Bouncy Castle provider
        Security.addProvider(new BouncyCastleProvider());

        try {

            // Wait for the user to start the Connection
            BufferedReader start = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to proceed...");
            start.readLine();

            BcTlsCrypto crypto = new BcTlsCrypto(new SecureRandom());

            // Open a socket connection
            Socket socket = new Socket(HOST, PORT);
            InputStream inputStream = socket.getInputStream();
            OutputStream outputStream = socket.getOutputStream();

            // Create a TLS client protocol handler
            TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(inputStream, outputStream);

            // Implement a simple TLS client using Bouncy Castle
            TlsClient client = new DefaultTlsClient(crypto) {
                @Override
                public ProtocolVersion[] getProtocolVersions() {
                    // Restrict Version to TLSv1.2
                    return new ProtocolVersion[] { ProtocolVersion.TLSv12 };
                }

                @Override
                public TlsAuthentication getAuthentication() throws IOException {
                    return new TlsAuthentication() {
                        @Override
                        public void notifyServerCertificate(TlsServerCertificate serverCertificate) throws IOException {
                            // Trust all certificates
                        }

                        @Override
                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                            return null; // No client authentication
                        }
                    };
                }
            };

            // Start the TLS handshake
            tlsClientProtocol.connect(client);
            System.out.println("Connected to " + HOST + ":" + PORT);
            
            // Keep connection open by waiting for user input
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to disconnect...");
            reader.readLine();

            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

