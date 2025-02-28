package com.example.test_client_12_bouncycastle_key_export;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.*;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.bc.BcTlsSecret;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestClient12BouncyCastleKeyExport {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 4432;
    private static byte[] clientRandom;
    private static byte[] masterSecret;
    private static TlsSecret masterSecretObj;
    private static boolean loggedMasterSecret = false;

    public static void main(String[] args) {
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

            Thread handshake = new Thread(() -> {
                try {
                    // Start the TLS handshake
                    tlsClientProtocol.connect(client);
                } catch (Exception e) {
                    e.printStackTrace();
                }    
            });

            Thread checkSecretThread = new Thread(() -> {
                Field clientContextField = null;
                TlsClientContext clientContext = null;
                SecurityParameters securityParameters = null;
                try {
                    // Get Master Secret if available
                    while (!loggedMasterSecret) {
                        while(clientContext == null) {
                            // Get the Context using reflection
                            clientContextField = getFieldFromClassHierarchy(DefaultTlsClient.class, "context");
                            clientContextField.setAccessible(true);
                            clientContext = (TlsClientContext) clientContextField.get(client);
                            Thread.sleep(1);
                        }
                        // Get the SecurityParameters using reflection
                        Method getSecurityParametersMethod = clientContext.getClass().getMethod("getSecurityParameters");
                        getSecurityParametersMethod.setAccessible(true);
                        securityParameters =(SecurityParameters) getSecurityParametersMethod.invoke(clientContext);

                        // Get the Master Secret using reflection
                        Field masterSecretField = getFieldFromClassHierarchy(SecurityParameters.class, "masterSecret");
                        masterSecretField.setAccessible(true);
                        masterSecretObj = (TlsSecret) masterSecretField.get(securityParameters);

                        if (masterSecretObj != null) {
                            Method copyData = BcTlsSecret.class.getSuperclass().getDeclaredMethod("copyData");
                            copyData.setAccessible(true);
                            masterSecret = (byte[]) copyData.invoke(masterSecretObj);
                            loggedMasterSecret = true;
                        }
                        Thread.sleep(1);                        
                    }
                    // Get Client Random and print with master secret
                    clientRandom = securityParameters.getClientRandom();
                    System.out.println("CLIENT_RANDOM " + bytesToHex(clientRandom) + " " + bytesToHex(masterSecret));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            checkSecretThread.start();
            handshake.start();
            
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
    
    private static Field getFieldFromClassHierarchy(Class<?> clazz, String fieldName) {
        // Iterate through the class hierarchy to find the field
        while (clazz != null) {
            try {
                return clazz.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                // Move to the superclass if not found in the current class
                clazz = clazz.getSuperclass();
            }
        }
        System.out.println("Field not found: " + fieldName);
        return null;
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hexArray = "0123456789ABCDEF".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}
