package com.example.tls_library_ground_truth.BouncyCastle;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import kotlin.UByte;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClient;
import org.bouncycastle.tls.TlsClientContext;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.tls.crypto.impl.p018bc.BcTlsCrypto;
import org.bouncycastle.tls.crypto.impl.p018bc.BcTlsSecret;

/* loaded from: classes.dex */
public class TestClient13BouncyCastleKeyExport {
    private static byte[] clientHandshakeSecret = null;
    private static TlsSecret clientHandshakeSecretObj = null;
    private static byte[] clientRandom = null;
    private static byte[] clientTrafficSecret = null;
    private static TlsSecret clientTrafficSecretObj = null;
    private static boolean handshakeComplete = false;
    private static boolean loggedMasterSecret = false;
    private static byte[] masterSecret = null;
    private static TlsSecret masterSecretObj = null;
    private static boolean ready_to_return = false;
    private static byte[] serverHandshakeSecret;
    private static TlsSecret serverHandshakeSecretObj;
    private static byte[] serverTrafficSecret;
    private static TlsSecret serverTrafficSecretObj;
    private static Socket socket_bouncy_13_ex;
    private static String HOST = "10.0.2.2";
    private static int PORT = 4433;
    private static String return_string = "Connected to " + HOST + ":" + PORT + " KEYLOG:";

    public static String run_bouncy_13_ex(String str, int i) {
        HOST = str;
        PORT = i;
        return_string = "Connected to " + HOST + ":" + PORT + " KEYLOG:";
        Security.addProvider(new BouncyCastleProvider());
        try {
            BcTlsCrypto bcTlsCrypto = new BcTlsCrypto(new SecureRandom());
            Socket socket = new Socket(HOST, PORT);
            socket_bouncy_13_ex = socket;
            final TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(), socket_bouncy_13_ex.getOutputStream());
            final DefaultTlsClient defaultTlsClient = new DefaultTlsClient(bcTlsCrypto) { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastleKeyExport.1
                @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsPeer
                public ProtocolVersion[] getProtocolVersions() {
                    return new ProtocolVersion[]{ProtocolVersion.TLSv13};
                }

                @Override // org.bouncycastle.tls.TlsClient
                public TlsAuthentication getAuthentication() throws IOException {
                    return new TlsAuthentication() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastleKeyExport.1.1
                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                            return null;
                        }

                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                        }

                        {
                            C05901.this = this;
                        }
                    };
                }
            };
            Thread thread = new Thread(new Runnable() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastleKeyExport$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    TestClient13BouncyCastleKeyExport.lambda$run_bouncy_13_ex$0(TlsClientProtocol.this, defaultTlsClient);
                }
            });
            new Thread(new Runnable() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient13BouncyCastleKeyExport$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    TestClient13BouncyCastleKeyExport.lambda$run_bouncy_13_ex$1(TlsClient.this);
                }
            }).start();
            thread.start();
            while (!ready_to_return) {
                Thread.sleep(1L);
            }
            return return_string;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }

    public static /* synthetic */ void lambda$run_bouncy_13_ex$0(TlsClientProtocol tlsClientProtocol, TlsClient tlsClient) {
        try {
            tlsClientProtocol.connect(tlsClient);
            handshakeComplete = true;
            System.out.println("Connected to " + HOST + ":" + PORT);
            tlsClientProtocol.getOutputStream().write("Hello, World more text bla bvlaksomopop".getBytes());
            tlsClientProtocol.getOutputStream().flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static /* synthetic */ void lambda$run_bouncy_13_ex$1(TlsClient tlsClient) {
        long j;
        boolean z;
        SecurityParameters securityParameters = null;
        TlsClientContext tlsClientContext = null;
        while (!loggedMasterSecret) {
            try {
                while (tlsClientContext == null) {
                    Field fieldFromClassHierarchy = getFieldFromClassHierarchy(DefaultTlsClient.class, "context");
                    fieldFromClassHierarchy.setAccessible(true);
                    tlsClientContext = (TlsClientContext) fieldFromClassHierarchy.get(tlsClient);
                    Thread.sleep(1L);
                }
                Method method = tlsClientContext.getClass().getMethod("getSecurityParameters", new Class[0]);
                method.setAccessible(true);
                securityParameters = (SecurityParameters) method.invoke(tlsClientContext, new Object[0]);
                Field fieldFromClassHierarchy2 = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretClient");
                fieldFromClassHierarchy2.setAccessible(true);
                clientHandshakeSecretObj = (TlsSecret) fieldFromClassHierarchy2.get(securityParameters);
                Field fieldFromClassHierarchy3 = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretServer");
                fieldFromClassHierarchy3.setAccessible(true);
                TlsSecret tlsSecret = (TlsSecret) fieldFromClassHierarchy3.get(securityParameters);
                serverHandshakeSecretObj = tlsSecret;
                if (clientHandshakeSecretObj == null || tlsSecret == null) {
                    j = 1;
                } else {
                    Method declaredMethod = BcTlsSecret.class.getSuperclass().getDeclaredMethod("copyData", new Class[0]);
                    declaredMethod.setAccessible(true);
                    clientHandshakeSecret = (byte[]) declaredMethod.invoke(clientHandshakeSecretObj, new Object[0]);
                    serverHandshakeSecret = (byte[]) declaredMethod.invoke(serverHandshakeSecretObj, new Object[0]);
                    loggedMasterSecret = true;
                    while (true) {
                        z = handshakeComplete;
                        if (z) {
                            break;
                        }
                        Thread.sleep(1L);
                    }
                    if (z) {
                        Field fieldFromClassHierarchy4 = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretClient");
                        fieldFromClassHierarchy4.setAccessible(true);
                        clientTrafficSecretObj = (TlsSecret) fieldFromClassHierarchy4.get(securityParameters);
                        Field fieldFromClassHierarchy5 = getFieldFromClassHierarchy(SecurityParameters.class, "trafficSecretServer");
                        fieldFromClassHierarchy5.setAccessible(true);
                        serverTrafficSecretObj = (TlsSecret) fieldFromClassHierarchy5.get(securityParameters);
                        clientTrafficSecret = (byte[]) declaredMethod.invoke(clientTrafficSecretObj, new Object[0]);
                        serverTrafficSecret = (byte[]) declaredMethod.invoke(serverTrafficSecretObj, new Object[0]);
                    }
                    j = 1;
                }
                Thread.sleep(j);
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        clientRandom = securityParameters.getClientRandom();
        System.out.println("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(clientRandom) + " " + bytesToHex(clientHandshakeSecret));
        System.out.println("SERVER_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(clientRandom) + " " + bytesToHex(serverHandshakeSecret));
        System.out.println("CLIENT_TRAFFIC_SECRET_0 " + bytesToHex(clientRandom) + " " + bytesToHex(clientTrafficSecret));
        System.out.println("SERVER_TRAFFIC_SECRET_0 " + bytesToHex(clientRandom) + " " + bytesToHex(serverTrafficSecret));
        return_string += "CLIENT_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(clientRandom) + " " + bytesToHex(clientHandshakeSecret);
        return_string += "SERVER_HANDSHAKE_TRAFFIC_SECRET " + bytesToHex(clientRandom) + " " + bytesToHex(serverHandshakeSecret);
        return_string += "CLIENT_TRAFFIC_SECRET_0 " + bytesToHex(clientRandom) + " " + bytesToHex(clientTrafficSecret);
        return_string += "SERVER_TRAFFIC_SECRET_0 " + bytesToHex(clientRandom) + " " + bytesToHex(serverTrafficSecret);
        ready_to_return = true;
    }

    public static String close_bouncy_13_ex() {
        try {
            Socket socket = socket_bouncy_13_ex;
            if (socket != null) {
                socket.close();
                System.out.println("Closed connection");
                return "Closed connection";
            }
            return "Error";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }

    private static Field getFieldFromClassHierarchy(Class<?> cls, String str) {
        while (cls != null) {
            try {
                return cls.getDeclaredField(str);
            } catch (NoSuchFieldException unused) {
                cls = cls.getSuperclass();
            }
        }
        System.out.println("Field not found: " + str);
        return null;
    }

    private static String bytesToHex(byte[] bArr) {
        char[] charArray = "0123456789ABCDEF".toCharArray();
        char[] cArr = new char[bArr.length * 2];
        for (int i = 0; i < bArr.length; i++) {
            byte b = bArr[i];
            int i2 = i * 2;
            cArr[i2] = charArray[(b & UByte.MAX_VALUE) >>> 4];
            cArr[i2 + 1] = charArray[b & 15];
        }
        return new String(cArr);
    }
}