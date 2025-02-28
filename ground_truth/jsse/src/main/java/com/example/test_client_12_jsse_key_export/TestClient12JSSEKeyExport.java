package com.example.test_client_12_jsse_key_export;

import javax.net.ssl.*;

import java.io.*;
import java.security.cert.X509Certificate;

public class TestClient12JSSEKeyExport {
     
    public static void main(String[] args) {
        final String HOST = "127.0.0.1";
        final int PORT = 4432;

        try{
            // Wait for the user to start the Connection
            BufferedReader start = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to proceed...");
            start.readLine();
            
            SSLContext sslContext = SSLContext.getInstance("TLS");

            // Create a TrustManager that trusts all certificates
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public java.security.cert.X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }

                    public void checkClientTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                    }

                    public void checkServerTrusted(
                        java.security.cert.X509Certificate[] certs, String authType) {
                    }
                }
            };

            // Initialize the SSLContext with no KeyManager
            sslContext.init(null, trustAllCerts, null);

            // Create socket factory
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket(HOST, PORT);
            LoggingSSLSocket loggingSocket = new LoggingSSLSocket(socket);

            // Set the enabled protocols to TLSv1.2
            loggingSocket.setEnabledProtocols(new String[] {"TLSv1.2"});

            loggingSocket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    System.out.println("Handshake finished!");
                }
            });

            // Start handshake
            loggingSocket.startHandshake();
            
            System.out.println("Connected to " + HOST + ":" + PORT);

            // Keep connection open by waiting for user input
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to disconnect...");
            reader.readLine();

            loggingSocket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        
    }

}
