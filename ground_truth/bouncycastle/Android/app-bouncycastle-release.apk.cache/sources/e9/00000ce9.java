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
public class TestClient12BouncyCastleKeyExport {
    private static byte[] clientRandom = null;
    private static boolean loggedMasterSecret = false;
    private static byte[] masterSecret = null;
    private static TlsSecret masterSecretObj = null;
    private static boolean ready_to_return = false;
    private static Socket socket_bouncy_12_ex;
    private static String HOST = "10.0.2.2";
    private static int PORT = 4433;
    private static String return_string = "Connected to " + HOST + ":" + PORT + " KEYLOG:";

    public static String run_bouncy_12_ex(String str, int i) {
        HOST = str;
        PORT = i;
        Security.addProvider(new BouncyCastleProvider());
        try {
            BcTlsCrypto bcTlsCrypto = new BcTlsCrypto(new SecureRandom());
            Socket socket = new Socket(HOST, PORT);
            socket_bouncy_12_ex = socket;
            final TlsClientProtocol tlsClientProtocol = new TlsClientProtocol(socket.getInputStream(), socket_bouncy_12_ex.getOutputStream());
            final DefaultTlsClient defaultTlsClient = new DefaultTlsClient(bcTlsCrypto) { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastleKeyExport.1
                @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsPeer
                public ProtocolVersion[] getProtocolVersions() {
                    return new ProtocolVersion[]{ProtocolVersion.TLSv12};
                }

                @Override // org.bouncycastle.tls.TlsClient
                public TlsAuthentication getAuthentication() throws IOException {
                    return new TlsAuthentication() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastleKeyExport.1.1
                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                            return null;
                        }

                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                        }

                        {
                            C05861.this = this;
                        }
                    };
                }
            };
            Thread thread = new Thread(new Runnable() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastleKeyExport$$ExternalSyntheticLambda0
                @Override // java.lang.Runnable
                public final void run() {
                    TestClient12BouncyCastleKeyExport.lambda$run_bouncy_12_ex$0(TlsClientProtocol.this, defaultTlsClient);
                }
            });
            new Thread(new Runnable() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastleKeyExport$$ExternalSyntheticLambda1
                @Override // java.lang.Runnable
                public final void run() {
                    TestClient12BouncyCastleKeyExport.lambda$run_bouncy_12_ex$1(TlsClient.this);
                }
            }).start();
            thread.start();
            System.out.println("Connected to " + HOST + ":" + PORT);
            while (!ready_to_return) {
                Thread.sleep(1L);
            }
            return return_string;
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }

    public static /* synthetic */ void lambda$run_bouncy_12_ex$0(TlsClientProtocol tlsClientProtocol, TlsClient tlsClient) {
        try {
            tlsClientProtocol.connect(tlsClient);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static /* synthetic */ void lambda$run_bouncy_12_ex$1(TlsClient tlsClient) {
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
                Field fieldFromClassHierarchy2 = getFieldFromClassHierarchy(SecurityParameters.class, "masterSecret");
                fieldFromClassHierarchy2.setAccessible(true);
                TlsSecret tlsSecret = (TlsSecret) fieldFromClassHierarchy2.get(securityParameters);
                masterSecretObj = tlsSecret;
                if (tlsSecret != null) {
                    Method declaredMethod = BcTlsSecret.class.getSuperclass().getDeclaredMethod("copyData", new Class[0]);
                    declaredMethod.setAccessible(true);
                    masterSecret = (byte[]) declaredMethod.invoke(masterSecretObj, new Object[0]);
                    loggedMasterSecret = true;
                }
                Thread.sleep(1L);
            } catch (Exception e) {
                e.printStackTrace();
                return;
            }
        }
        clientRandom = securityParameters.getClientRandom();
        System.out.println("CLIENT_RANDOM " + bytesToHex(clientRandom) + " " + bytesToHex(masterSecret));
        return_string += "CLIENT_RANDOM " + bytesToHex(clientRandom) + " " + bytesToHex(masterSecret);
        ready_to_return = true;
    }

    public static String close_bouncy_12_ex() {
        try {
            Socket socket = socket_bouncy_12_ex;
            if (socket != null) {
                socket.close();
                System.out.println("Closed connetion");
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