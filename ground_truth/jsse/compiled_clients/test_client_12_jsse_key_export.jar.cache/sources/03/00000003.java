package com.example.test_client_12_jsse_key_export;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.SocketAddress;
import javax.crypto.SecretKey;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* loaded from: test_client_12_jsse_key_export.jar:com/example/test_client_12_jsse_key_export/LoggingSSLSocket.class */
public class LoggingSSLSocket extends SSLSocket {
    private final SSLSocket sslSocket;
    private boolean random_printed = false;
    private String clientRandom = "-1";

    public LoggingSSLSocket(SSLSocket sslSocket) {
        this.sslSocket = sslSocket;
    }

    @Override // javax.net.ssl.SSLSocket
    public void startHandshake() throws IOException {
        this.sslSocket.addHandshakeCompletedListener(event -> {
            try {
                logSessionKeys();
            } catch (Exception e) {
                System.out.println("Failed to log session keys: " + e.getMessage());
            }
        });
        Thread randomCheckThread = new Thread(() -> {
            while (!this.random_printed) {
                try {
                    this.clientRandom = checkForClientRandom();
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
        randomCheckThread.start();
        this.sslSocket.startHandshake();
        try {
            randomCheckThread.join();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private String checkForClientRandom() {
        byte[] randomBytes;
        try {
            Class<?> sslSocketClass = this.sslSocket.getClass();
            Object transportContext = getFieldUsingReflection(sslSocketClass, this.sslSocket, "conContext");
            if (transportContext != null) {
                try {
                    Object handshakeContext = getFieldUsingReflection(transportContext.getClass(), transportContext, "handshakeContext");
                    if (handshakeContext != null) {
                        Field clientHelloRandomField = getFieldFromClassHierarchy(handshakeContext.getClass(), "clientHelloRandom");
                        if (clientHelloRandomField != null) {
                            clientHelloRandomField.setAccessible(true);
                            Object clientHelloRandom = clientHelloRandomField.get(handshakeContext);
                            if (clientHelloRandom != null && (randomBytes = (byte[]) getFieldUsingReflection(clientHelloRandom.getClass(), clientHelloRandom, "randomBytes")) != null) {
                                String random = "CLIENT_RANDOM " + bytesToHex(randomBytes);
                                this.random_printed = true;
                                return random;
                            }
                        } else {
                            System.out.println("Field 'clientHelloRandom' not found in the class hierarchy.");
                        }
                    }
                } catch (NoSuchFieldException e) {
                    System.out.println("Field 'handshakeContext' not found in the class hierarchy.");
                }
            }
            return "-1";
        } catch (Exception e2) {
            e2.printStackTrace();
            return "-1";
        }
    }

    private void logSessionKeys() {
        try {
            SSLSession session = this.sslSocket.getSession();
            Object masterSecret = getFieldUsingReflection(session.getClass(), session, "masterSecret");
            if (masterSecret instanceof SecretKey) {
                byte[] secretBytes = ((SecretKey) masterSecret).getEncoded();
                System.out.println(this.clientRandom + " " + bytesToHex(secretBytes));
            } else {
                System.out.println("Master secret is not an instance of javax.crypto.SecretKey");
            }
        } catch (Exception e) {
            System.out.println("Failed to log session keys: " + e.getMessage());
        }
    }

    private Object getFieldUsingReflection(Class<?> targetClass, Object obj, String fieldName) throws Exception {
        Field field = targetClass.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    private Field getFieldFromClassHierarchy(Class<?> clazz, String fieldName) {
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 255;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[(j * 2) + 1] = hexArray[v & 15];
        }
        return new String(hexChars);
    }

    @Override // java.net.Socket
    public void connect(SocketAddress endpoint) throws IOException {
        this.sslSocket.connect(endpoint);
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getSupportedCipherSuites() {
        return this.sslSocket.getSupportedCipherSuites();
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getEnabledCipherSuites() {
        return this.sslSocket.getEnabledCipherSuites();
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnabledCipherSuites(String[] suites) {
        this.sslSocket.setEnabledCipherSuites(suites);
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getSupportedProtocols() {
        return this.sslSocket.getSupportedProtocols();
    }

    @Override // javax.net.ssl.SSLSocket
    public String[] getEnabledProtocols() {
        return this.sslSocket.getEnabledProtocols();
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnabledProtocols(String[] protocols) {
        this.sslSocket.setEnabledProtocols(protocols);
    }

    @Override // javax.net.ssl.SSLSocket
    public SSLSession getSession() {
        return this.sslSocket.getSession();
    }

    @Override // javax.net.ssl.SSLSocket
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        this.sslSocket.addHandshakeCompletedListener(listener);
    }

    @Override // javax.net.ssl.SSLSocket
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        this.sslSocket.removeHandshakeCompletedListener(listener);
    }

    @Override // javax.net.ssl.SSLSocket
    public void setUseClientMode(boolean mode) {
        this.sslSocket.setUseClientMode(mode);
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getUseClientMode() {
        return this.sslSocket.getUseClientMode();
    }

    @Override // javax.net.ssl.SSLSocket
    public void setNeedClientAuth(boolean need) {
        this.sslSocket.setNeedClientAuth(need);
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getNeedClientAuth() {
        return this.sslSocket.getNeedClientAuth();
    }

    @Override // javax.net.ssl.SSLSocket
    public void setWantClientAuth(boolean want) {
        this.sslSocket.setWantClientAuth(want);
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getWantClientAuth() {
        return this.sslSocket.getWantClientAuth();
    }

    @Override // javax.net.ssl.SSLSocket
    public void setEnableSessionCreation(boolean flag) {
        this.sslSocket.setEnableSessionCreation(flag);
    }

    @Override // javax.net.ssl.SSLSocket
    public boolean getEnableSessionCreation() {
        return this.sslSocket.getEnableSessionCreation();
    }
}