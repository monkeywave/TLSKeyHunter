package com.example.test_client_13_jsse;

import javax.net.ssl.*;
import java.io.*;
import java.security.cert.X509Certificate;

public class TestClient13JSSE{
    
    public static void main(String[] args) {
        final String HOST = "127.0.0.1";
        final int PORT = 4433;

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

            // Set the enabled protocols to TLSv1.3
            socket.setEnabledProtocols(new String[] {"TLSv1.3"});

            // Start handshake
            socket.startHandshake();
            
            System.out.println("Connected to " + HOST + ":" + PORT);

            // Get session after the connection is established and print Version
            SSLSession session = socket.getSession();
            System.out.println("Session established with TLS version: " + session.getProtocol());

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

