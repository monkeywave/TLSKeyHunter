package com.example.test_client_13_jsse_key_export;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.SocketAddress;
import java.util.List;
import javax.crypto.SecretKey;
import javax.net.ssl.HandshakeCompletedListener;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/* loaded from: test_client_12_jsse_key_export.jar:com/example/test_client_13_jsse_key_export/LoggingSSLSocket.class */
public class LoggingSSLSocket extends SSLSocket {
    private final SSLSocket sslSocket;
    private boolean random_printed = false;
    private boolean secretPrinted = false;
    private byte[] clientRandom;
    private byte[] clientHandshakeTrafficSecret;
    private byte[] serverHandshakeTrafficSecret;
    String usedCipher;

    public LoggingSSLSocket(SSLSocket sslSocket) {
        this.sslSocket = sslSocket;
    }

    @Override // javax.net.ssl.SSLSocket
    public void startHandshake() throws IOException {
        this.sslSocket.addHandshakeCompletedListener(event -> {
            try {
                this.secretPrinted = true;
                getUsedCipherSuite();
                this.sslSocket.getOutputStream().write("Hello, server!".getBytes());
                this.sslSocket.getOutputStream().flush();
                System.out.println("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(this.clientRandom) + " " + bytesToHex(this.clientHandshakeTrafficSecret));
                System.out.println("SERVER_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(this.clientRandom) + " " + bytesToHex(this.serverHandshakeTrafficSecret));
            } catch (Exception e) {
                System.out.println("Failed to log session keys: " + e.getMessage());
            }
        });
        Thread randomCheckThread = new Thread(() -> {
            Object handshakeContext;
            while (!this.random_printed) {
                try {
                    checkForClientRandom();
                    Thread.sleep(1L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            while (!this.secretPrinted) {
                try {
                    Object conContext = getFieldUsingReflection(this.sslSocket.getClass(), this.sslSocket, "conContext");
                    if (conContext != null && (handshakeContext = getFieldUsingReflection(conContext.getClass(), conContext, "handshakeContext")) != null) {
                        Field baseWriteField = getFieldFromClassHierarchy(handshakeContext.getClass(), "baseWriteSecret");
                        Field baseReadField = getFieldFromClassHierarchy(handshakeContext.getClass(), "baseReadSecret");
                        if (baseWriteField != null && baseReadField != null) {
                            baseWriteField.setAccessible(true);
                            baseReadField.setAccessible(true);
                            SecretKey baseWriteSecret = (SecretKey) baseWriteField.get(handshakeContext);
                            SecretKey baseReadSecret = (SecretKey) baseReadField.get(handshakeContext);
                            this.clientHandshakeTrafficSecret = baseWriteSecret.getEncoded();
                            this.serverHandshakeTrafficSecret = baseReadSecret.getEncoded();
                            this.secretPrinted = true;
                        }
                    }
                } catch (Exception e2) {
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

    private void checkForClientRandom() {
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
                                this.clientRandom = randomBytes;
                                this.random_printed = true;
                            }
                        } else {
                            System.out.println("Field 'clientHelloRandom' not found in the class hierarchy.");
                        }
                    }
                } catch (NoSuchFieldException e) {
                    System.out.println("Field 'handshakeContext' not found in the class hierarchy.");
                }
            }
        } catch (Exception e2) {
            e2.printStackTrace();
        }
    }

    private void getUsedCipherSuite() {
        try {
            SSLSession session = this.sslSocket.getSession();
            Object cipherSuiteObj = getFieldUsingReflection(session.getClass(), session, "cipherSuite");
            this.usedCipher = cipherSuiteObj.toString();
        } catch (Exception e) {
            System.out.println("Failed to get ciphersuite: " + e.getMessage());
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

    public static boolean compareByteArrays(byte[] array1, byte[] array2) {
        if (array1.length != array2.length) {
            return false;
        }
        for (int i = 0; i < array1.length; i++) {
            if (array1[i] != array2[i]) {
                return false;
            }
        }
        return true;
    }

    public boolean isByteArrayInList(List<byte[]> list, byte[] targetArray) {
        for (byte[] array : list) {
            if (compareByteArrays(array, targetArray)) {
                return true;
            }
        }
        return false;
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