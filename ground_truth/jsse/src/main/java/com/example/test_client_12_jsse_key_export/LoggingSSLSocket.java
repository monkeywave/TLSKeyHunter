package com.example.test_client_12_jsse_key_export;

/*
 * Based on: https://github.com/neykov/extract-tls-secrets
 */
import javax.net.ssl.*;
import java.io.IOException;
import java.lang.reflect.Field;

public class LoggingSSLSocket extends SSLSocket {
    private final SSLSocket sslSocket;
    private boolean random_printed = false;
    private String clientRandom = "-1";

    // Constructor that wraps an existing SSLSocket instance
    public LoggingSSLSocket(SSLSocket sslSocket) {
        this.sslSocket = sslSocket;
    }

    @Override
    public void startHandshake() throws IOException {
        // Add a listener to Handshake to ensure the master secret is available for logging
        sslSocket.addHandshakeCompletedListener(event ->{
            try{
                // extract the session keys
                logSessionKeys();
            } catch (Exception e) {
                System.out.println("Failed to log session keys: " + e.getMessage());
            }
        });

        /* 
        * Start a thread to check for the client random during handshake
        * This is needed because the handshakeContext is not available after the handshake is completed
        */
        Thread randomCheckThread = new Thread(() -> {
            try{
                while (!random_printed) {
                    clientRandom = checkForClientRandom();
                    Thread.sleep(1);
                }
            }catch (InterruptedException e){
                Thread.currentThread().interrupt();
            }
        });
        randomCheckThread.start();

        // Start the handshake
        sslSocket.startHandshake();

        // Ensure the random check thread is stopped after the handshake
        try{
            randomCheckThread.join();
        } catch (InterruptedException e){
            Thread.currentThread().interrupt();
        }

    }

    private String checkForClientRandom() {
        try {
            // Get transportContext from the wrapped sslSocket
            Class<?> sslSocketClass = sslSocket.getClass();
            Object transportContext = getFieldUsingReflection(sslSocketClass, sslSocket, "conContext");
    
            if (transportContext != null) {
                try {
                    // Get handshakeContext from transportContext using reflection
                    Object handshakeContext = getFieldUsingReflection(transportContext.getClass(), transportContext, "handshakeContext");
                    if (handshakeContext != null) {
                        // Iterate through the class hierarchy to find clientHelloRandom
                        Field clientHelloRandomField = getFieldFromClassHierarchy(handshakeContext.getClass(), "clientHelloRandom");
                        
                        if (clientHelloRandomField != null) {
                            clientHelloRandomField.setAccessible(true);
                            Object clientHelloRandom = clientHelloRandomField.get(handshakeContext);
                            
                            if (clientHelloRandom != null) {
                                // Assuming clientHelloRandom is an instance of RandomCookie
                                byte[] randomBytes = (byte[]) getFieldUsingReflection(clientHelloRandom.getClass(), clientHelloRandom, "randomBytes");
                                if (randomBytes != null) {
                                    // Store the extracted client random in a readable format
                                    String random = "CLIENT_RANDOM " + bytesToHex(randomBytes);
                                    random_printed = true;
                                    return random;
                                }
                            }
                        } else {
                            System.out.println("Field 'clientHelloRandom' not found in the class hierarchy.");
                        }
                    }
                } catch (NoSuchFieldException e) {
                    System.out.println("Field 'handshakeContext' not found in the class hierarchy.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "-1";
    }

    private void logSessionKeys() {
        try {            
            // Access master secret using reflection and get its encoded form
            SSLSession session = sslSocket.getSession();
            Object masterSecret = getFieldUsingReflection(session.getClass(), session, "masterSecret");
    
            if (masterSecret instanceof javax.crypto.SecretKey) {
                byte[] secretBytes = ((javax.crypto.SecretKey) masterSecret).getEncoded();
                // Print the client random and master secret
                System.out.println(clientRandom + " " + bytesToHex(secretBytes));                
            } else {
                System.out.println("Master secret is not an instance of javax.crypto.SecretKey");
            }

        } catch (Exception e) {
            System.out.println("Failed to log session keys: " + e.getMessage());
        }
    }    

    private Object getFieldUsingReflection(Class<?> targetClass, Object obj, String fieldName) throws Exception {
        // Implement reflection logic to access private fields in session objects
        java.lang.reflect.Field field = targetClass.getDeclaredField(fieldName);
        field.setAccessible(true);
        return field.get(obj);
    }

    private Field getFieldFromClassHierarchy(Class<?> clazz, String fieldName) {
        // Iterate through the class hierarchy to find the field
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                // Move to the superclass if not found in the current class
                clazz = clazz.getSuperclass();
            }
        }
        return null;
    }

    private String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    // Override other SSLSocket methods to delegate to the wrapped instance
    @Override
    public void connect(java.net.SocketAddress endpoint) throws IOException {
        sslSocket.connect(endpoint);
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return sslSocket.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return sslSocket.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(String[] suites) {
        sslSocket.setEnabledCipherSuites(suites);
    }

    @Override
    public String[] getSupportedProtocols() {
        return sslSocket.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return sslSocket.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(String[] protocols) {
        sslSocket.setEnabledProtocols(protocols);
    }

    @Override
    public SSLSession getSession() {
        return sslSocket.getSession();
    }

    @Override
    public void addHandshakeCompletedListener(HandshakeCompletedListener listener) {
        sslSocket.addHandshakeCompletedListener(listener);
    }

    @Override
    public void removeHandshakeCompletedListener(HandshakeCompletedListener listener) {
        sslSocket.removeHandshakeCompletedListener(listener);
    }

    @Override
    public void setUseClientMode(boolean mode) {
        sslSocket.setUseClientMode(mode);
    }

    @Override
    public boolean getUseClientMode() {
        return sslSocket.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(boolean need) {
        sslSocket.setNeedClientAuth(need);
    }

    @Override
    public boolean getNeedClientAuth() {
        return sslSocket.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(boolean want) {
        sslSocket.setWantClientAuth(want);
    }

    @Override
    public boolean getWantClientAuth() {
        return sslSocket.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(boolean flag) {
        sslSocket.setEnableSessionCreation(flag);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return sslSocket.getEnableSessionCreation();
    }
}