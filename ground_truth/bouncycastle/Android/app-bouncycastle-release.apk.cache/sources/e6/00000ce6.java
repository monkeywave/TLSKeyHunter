package com.example.tls_library_ground_truth.BouncyCastle;

import java.io.IOException;
import java.net.Socket;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.tls.CertificateRequest;
import org.bouncycastle.tls.DefaultTlsClient;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.TlsAuthentication;
import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsCredentials;
import org.bouncycastle.tls.TlsServerCertificate;
import org.bouncycastle.tls.crypto.impl.p018bc.BcTlsCrypto;

/* loaded from: classes.dex */
public class TestClient12BouncyCastle {
    private static String HOST = "10.0.2.2";
    private static int PORT = 4433;
    static Socket socket_bouncy_12;

    public static String run_bouncy_12(String str, int i) {
        HOST = str;
        PORT = i;
        Security.addProvider(new BouncyCastleProvider());
        try {
            BcTlsCrypto bcTlsCrypto = new BcTlsCrypto(new SecureRandom());
            Socket socket = new Socket(HOST, PORT);
            socket_bouncy_12 = socket;
            new TlsClientProtocol(socket.getInputStream(), socket_bouncy_12.getOutputStream()).connect(new DefaultTlsClient(bcTlsCrypto) { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastle.1
                @Override // org.bouncycastle.tls.AbstractTlsClient, org.bouncycastle.tls.TlsPeer
                public ProtocolVersion[] getProtocolVersions() {
                    return new ProtocolVersion[]{ProtocolVersion.TLSv12};
                }

                @Override // org.bouncycastle.tls.TlsClient
                public TlsAuthentication getAuthentication() throws IOException {
                    return new TlsAuthentication() { // from class: com.example.tls_library_ground_truth.BouncyCastle.TestClient12BouncyCastle.1.1
                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public TlsCredentials getClientCredentials(CertificateRequest certificateRequest) {
                            return null;
                        }

                        @Override // org.bouncycastle.tls.TlsAuthentication
                        public void notifyServerCertificate(TlsServerCertificate tlsServerCertificate) throws IOException {
                        }
                    };
                }
            });
            System.out.println("Connected to " + HOST + ":" + PORT);
            return "Connected to " + HOST + ":" + PORT + " KEYLOG: ";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }

    public static String close_bouncy_12() {
        try {
            Socket socket = socket_bouncy_12;
            if (socket != null) {
                socket.close();
                System.out.println("Closed connection");
                return "Closed Connection";
            }
            return "Error";
        } catch (Exception e) {
            e.printStackTrace();
            return "Error";
        }
    }
}