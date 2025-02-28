package com.example.test_client_13_bouncycastle_key_export;

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

public class TestClient13BouncyCastleKeyExport {
    private static final String HOST = "127.0.0.1";
    private static final int PORT = 4433;
    private static byte[] clientRandom;
    private static byte[] masterSecret;
    private static TlsSecret masterSecretObj;
    private static boolean loggedMasterSecret = false;
    private static boolean handshakeComplete = false;

    private static TlsSecret clientHandshakeSecretObj;
    private static byte[] clientHandshakeSecret;
    private static TlsSecret serverHandshakeSecretObj;
    private static byte[] serverHandshakeSecret;

    private static TlsSecret clientTrafficSecretObj;
    private static byte[] clientTrafficSecret;
    private static TlsSecret serverTrafficSecretObj;
    private static byte[] serverTrafficSecret;

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
                    // Restrict Version to TLSv1.3
                    return new ProtocolVersion[] { ProtocolVersion.TLSv13 };
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
                    handshakeComplete = true;
                    System.out.println("Connected to " + HOST + ":" + PORT);
                    
                    String testString = "Hello, World more text bla bvlaksomopop";
                    tlsClientProtocol.getOutputStream().write(testString.getBytes());
                    tlsClientProtocol.getOutputStream().flush();

                    // Keep connection open by waiting for user input
                    BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                    System.out.println("Press Enter to disconnect...");
                    reader.readLine();

                    socket.close();
                } catch (Exception e) {
                    e.printStackTrace();
                }    
            });

            Thread checkSecretThread = new Thread(() -> {
                Field clientContextField = null;
                TlsClientContext clientContext = null;
                SecurityParameters securityParameters = null;
                try {
                    // Get Secrets if available
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

                        /*
                         * Before handshake completion the traffic secrets are equal to handshake secrets
                         */
                        
                        // Get the Client Handshake Secret using reflection
                        Field clientHandshakeSecretField = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretClient");
                        clientHandshakeSecretField.setAccessible(true);
                        clientHandshakeSecretObj = (TlsSecret) clientHandshakeSecretField.get(securityParameters);

                        // Get the Server Handshake Secret using reflection
                        Field serverHandshakeSecretField = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretServer");
                        serverHandshakeSecretField.setAccessible(true);
                        serverHandshakeSecretObj = (TlsSecret) serverHandshakeSecretField.get(securityParameters);


                        if (clientHandshakeSecretObj != null && serverHandshakeSecretObj != null) {
                            Method copyData = BcTlsSecret.class.getSuperclass().getDeclaredMethod("copyData");
                            copyData.setAccessible(true);
                            
                            // copy client handshake secret
                            clientHandshakeSecret = (byte[]) copyData.invoke(clientHandshakeSecretObj);
                            // copy server handshake secret
                            serverHandshakeSecret = (byte[]) copyData.invoke(serverHandshakeSecretObj);                           
                            
                            loggedMasterSecret = true;

                            while(!handshakeComplete){
                                Thread.sleep(1);
                            }

                            /*
                             * After handshake completion the traffic secrets are available
                             */
                            if(handshakeComplete){
                                // Get the Client Traffic Secret using reflection
                                Field clientTrafficSecretField = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretClient");
                                clientTrafficSecretField.setAccessible(true);
                                clientTrafficSecretObj = (TlsSecret) clientTrafficSecretField.get(securityParameters);

                                // Get the Server Traffic Secret using reflection
                                Field serverTrafficSecretField = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretServer");
                                serverTrafficSecretField.setAccessible(true);
                                serverTrafficSecretObj = (TlsSecret) serverTrafficSecretField.get(securityParameters);

                                // copy client traffic secret
                                clientTrafficSecret = (byte[]) copyData.invoke(clientTrafficSecretObj);
                                // copy server traffic secret
                                serverTrafficSecret = (byte[]) copyData.invoke(serverTrafficSecretObj);
                            }
                        }
                        Thread.sleep(1);                        
                    }
                    // Get Client Random and print with master secret
                    clientRandom = securityParameters.getClientRandom();
                    System.out.println("CLIENT_HANDSHAKE_TRAFFIC_SECRET "+ bytesToHex(clientRandom) + " " + bytesToHex(clientHandshakeSecret));
                    System.out.println("SERVER_HANDSHAKE_TRAFFIC_SECRET "+ bytesToHex(clientRandom) + " " + bytesToHex(serverHandshakeSecret));
                    System.out.println("CLIENT_TRAFFIC_SECRET_0 "+ bytesToHex(clientRandom) + " " + bytesToHex(clientTrafficSecret));
                    System.out.println("SERVER_TRAFFIC_SECRET_0 "+ bytesToHex(clientRandom) + " " + bytesToHex(serverTrafficSecret));
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });

            checkSecretThread.start();
            handshake.start();
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
