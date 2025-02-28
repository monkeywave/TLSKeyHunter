package com.example.test_client_12_jsse;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.security.cert.X509Certificate;
import javax.net.ssl.HandshakeCompletedEvent;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/* loaded from: test_client_12_jsse_key_export.jar:com/example/test_client_12_jsse/TestClient12JSSE.class */
public class TestClient12JSSE {
    public static void main(String[] args) {
        try {
            BufferedReader start = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to proceed...");
            start.readLine();
            SSLContext sslContext = SSLContext.getInstance("TLS");
            TrustManager[] trustAllCerts = {new X509TrustManager() { // from class: com.example.test_client_12_jsse.TestClient12JSSE.1
                @Override // javax.net.ssl.X509TrustManager
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }

                @Override // javax.net.ssl.X509TrustManager
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }};
            sslContext.init(null, trustAllCerts, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket("127.0.0.1", 4433);
            socket.setEnabledProtocols(new String[]{"TLSv1.2"});
            socket.addHandshakeCompletedListener(new HandshakeCompletedListener() { // from class: com.example.test_client_12_jsse.TestClient12JSSE.2
                @Override // javax.net.ssl.HandshakeCompletedListener
                public void handshakeCompleted(HandshakeCompletedEvent event) {
                    System.out.println("Handshake finished!");
                }
            });
            socket.startHandshake();
            System.out.println("Connected to 127.0.0.1:4433");
            SSLSession session = socket.getSession();
            System.out.println("Session established with TLS version: " + session.getProtocol());
            BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Press Enter to disconnect...");
            reader.readLine();
            socket.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}