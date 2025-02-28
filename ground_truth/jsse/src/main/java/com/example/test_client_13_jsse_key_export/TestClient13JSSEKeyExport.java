package com.example.test_client_13_jsse_key_export;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import javax.net.ssl.*;

public class TestClient13JSSEKeyExport {
    public static void main(String[] args) {
        final String HOST = "127.0.0.1";
        final int PORT = 4433;
        try{
            Thread.sleep(10);
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
            // Unused (only exports handshake secrets)
            //LoggingSSLSocket loggingSocket = new LoggingSSLSocket(socket);

            // Set the enabled protocols to TLSv1.3
            socket.setEnabledProtocols(new String[] {"TLSv1.3"});

            socket.addHandshakeCompletedListener(new HandshakeCompletedListener() {
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    System.out.println("Press Enter to log secrets ...");
                }
            });

            // Start handshake
            socket.startHandshake();
            
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