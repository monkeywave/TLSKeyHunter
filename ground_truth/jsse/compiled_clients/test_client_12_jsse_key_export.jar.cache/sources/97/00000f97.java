package org.openjsse.sun.security.ssl;

import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.validator.Validator;
import sun.security.provider.certpath.AlgorithmChecker;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: SSLContextImpl.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/AbstractTrustManagerWrapper.class */
public final class AbstractTrustManagerWrapper extends X509ExtendedTrustManager implements X509TrustManager {

    /* renamed from: tm */
    private final X509TrustManager f959tm;

    /* JADX INFO: Access modifiers changed from: package-private */
    public AbstractTrustManagerWrapper(X509TrustManager tm) {
        this.f959tm = tm;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.f959tm.checkClientTrusted(chain, authType);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        this.f959tm.checkServerTrusted(chain, authType);
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return this.f959tm.getAcceptedIssuers();
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.f959tm.checkClientTrusted(chain, authType);
        checkAdditionalTrust(chain, authType, socket, true);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        this.f959tm.checkServerTrusted(chain, authType);
        checkAdditionalTrust(chain, authType, socket, false);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.f959tm.checkClientTrusted(chain, authType);
        checkAdditionalTrust(chain, authType, engine, true);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        this.f959tm.checkServerTrusted(chain, authType);
        checkAdditionalTrust(chain, authType, engine, false);
    }

    private void checkAdditionalTrust(X509Certificate[] chain, String authType, Socket socket, boolean checkClientTrusted) throws CertificateException {
        AlgorithmConstraints constraints;
        if (socket != null && socket.isConnected() && (socket instanceof SSLSocket)) {
            SSLSocket sslSocket = (SSLSocket) socket;
            SSLSession session = sslSocket.getHandshakeSession();
            if (session == null) {
                throw new CertificateException("No handshake session");
            }
            String identityAlg = sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm();
            if (identityAlg != null && identityAlg.length() != 0) {
                X509TrustManagerImpl.checkIdentity(session, chain, identityAlg, checkClientTrusted);
            }
            if (ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
                if (session instanceof ExtendedSSLSession) {
                    ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                    String[] peerSupportedSignAlgs = extSession.getLocalSupportedSignatureAlgorithms();
                    constraints = new SSLAlgorithmConstraints(sslSocket, peerSupportedSignAlgs, true);
                } else {
                    constraints = new SSLAlgorithmConstraints(sslSocket, true);
                }
            } else {
                constraints = new SSLAlgorithmConstraints(sslSocket, true);
            }
            checkAlgorithmConstraints(chain, constraints, checkClientTrusted);
        }
    }

    private void checkAdditionalTrust(X509Certificate[] chain, String authType, SSLEngine engine, boolean checkClientTrusted) throws CertificateException {
        AlgorithmConstraints constraints;
        if (engine != null) {
            SSLSession session = engine.getHandshakeSession();
            if (session == null) {
                throw new CertificateException("No handshake session");
            }
            String identityAlg = engine.getSSLParameters().getEndpointIdentificationAlgorithm();
            if (identityAlg != null && identityAlg.length() != 0) {
                X509TrustManagerImpl.checkIdentity(session, chain, identityAlg, checkClientTrusted);
            }
            if (ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
                if (session instanceof ExtendedSSLSession) {
                    ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                    String[] peerSupportedSignAlgs = extSession.getLocalSupportedSignatureAlgorithms();
                    constraints = new SSLAlgorithmConstraints(engine, peerSupportedSignAlgs, true);
                } else {
                    constraints = new SSLAlgorithmConstraints(engine, true);
                }
            } else {
                constraints = new SSLAlgorithmConstraints(engine, true);
            }
            checkAlgorithmConstraints(chain, constraints, checkClientTrusted);
        }
    }

    private void checkAlgorithmConstraints(X509Certificate[] chain, AlgorithmConstraints constraints, boolean checkClientTrusted) throws CertificateException {
        try {
            int checkedLength = chain.length - 1;
            Collection<X509Certificate> trustedCerts = new HashSet<>();
            X509Certificate[] certs = this.f959tm.getAcceptedIssuers();
            if (certs != null && certs.length > 0) {
                Collections.addAll(trustedCerts, certs);
            }
            if (trustedCerts.contains(chain[checkedLength])) {
                checkedLength--;
            }
            if (checkedLength >= 0) {
                AlgorithmChecker checker = new AlgorithmChecker(constraints, checkClientTrusted ? Validator.VAR_TLS_CLIENT : Validator.VAR_TLS_SERVER);
                checker.init(false);
                for (int i = checkedLength; i >= 0; i--) {
                    X509Certificate cert = chain[i];
                    checker.check(cert, Collections.emptySet());
                }
            }
        } catch (CertPathValidatorException cpve) {
            throw new CertificateException("Certificates do not conform to algorithm constraints", cpve);
        }
    }
}