package org.openjsse.sun.security.ssl;

import java.net.Socket;
import java.security.AlgorithmConstraints;
import java.security.cert.CertificateException;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.Iterator;
import java.util.List;
import javax.net.ssl.SNIHostName;
import javax.net.ssl.SNIServerName;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.openjsse.javax.net.ssl.ExtendedSSLSession;
import org.openjsse.javax.net.ssl.SSLSocket;
import org.openjsse.sun.security.util.HostnameChecker;
import org.openjsse.sun.security.validator.Validator;
import sun.security.util.AnchorCertificates;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/X509TrustManagerImpl.class */
public final class X509TrustManagerImpl extends X509ExtendedTrustManager implements X509TrustManager {
    private final String validatorType;
    private final Collection<X509Certificate> trustedCerts;
    private final PKIXBuilderParameters pkixParams;
    private volatile Validator clientValidator;
    private volatile Validator serverValidator;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509TrustManagerImpl(String validatorType, Collection<X509Certificate> trustedCerts) {
        this.validatorType = validatorType;
        this.pkixParams = null;
        trustedCerts = trustedCerts == null ? Collections.emptySet() : trustedCerts;
        this.trustedCerts = trustedCerts;
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,trustmanager")) {
            SSLLogger.fine("adding as trusted certificates", trustedCerts.toArray(new X509Certificate[0]));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509TrustManagerImpl(String validatorType, PKIXBuilderParameters params) {
        this.validatorType = validatorType;
        this.pkixParams = params;
        Validator v = getValidator(Validator.VAR_TLS_SERVER);
        this.trustedCerts = v.getTrustedCertificates();
        this.serverValidator = v;
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,trustmanager")) {
            SSLLogger.fine("adding as trusted certificates", this.trustedCerts.toArray(new X509Certificate[0]));
        }
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType, (Socket) null, true);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        checkTrusted(chain, authType, (Socket) null, false);
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        X509Certificate[] certsArray = new X509Certificate[this.trustedCerts.size()];
        this.trustedCerts.toArray(certsArray);
        return certsArray;
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(chain, authType, socket, true);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
        checkTrusted(chain, authType, socket, false);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkTrusted(chain, authType, engine, true);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
        checkTrusted(chain, authType, engine, false);
    }

    private Validator checkTrustedInit(X509Certificate[] chain, String authType, boolean checkClientTrusted) {
        Validator v;
        if (chain == null || chain.length == 0) {
            throw new IllegalArgumentException("null or zero-length certificate chain");
        }
        if (authType == null || authType.length() == 0) {
            throw new IllegalArgumentException("null or zero-length authentication type");
        }
        if (checkClientTrusted) {
            v = this.clientValidator;
            if (v == null) {
                synchronized (this) {
                    v = this.clientValidator;
                    if (v == null) {
                        v = getValidator(Validator.VAR_TLS_CLIENT);
                        this.clientValidator = v;
                    }
                }
            }
        } else {
            v = this.serverValidator;
            if (v == null) {
                synchronized (this) {
                    v = this.serverValidator;
                    if (v == null) {
                        v = getValidator(Validator.VAR_TLS_SERVER);
                        this.serverValidator = v;
                    }
                }
            }
        }
        return v;
    }

    private void checkTrusted(X509Certificate[] chain, String authType, Socket socket, boolean checkClientTrusted) throws CertificateException {
        X509Certificate[] trustedChain;
        AlgorithmConstraints constraints;
        Validator v = checkTrustedInit(chain, authType, checkClientTrusted);
        if (socket != null && socket.isConnected() && (socket instanceof SSLSocket)) {
            SSLSocket sslSocket = (SSLSocket) socket;
            SSLSession session = sslSocket.getHandshakeSession();
            if (session == null) {
                throw new CertificateException("No handshake session");
            }
            boolean isExtSession = session instanceof ExtendedSSLSession;
            if (isExtSession && ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
                ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                String[] localSupportedSignAlgs = extSession.getLocalSupportedSignatureAlgorithms();
                constraints = new SSLAlgorithmConstraints(sslSocket, localSupportedSignAlgs, false);
            } else {
                constraints = new SSLAlgorithmConstraints(sslSocket, false);
            }
            List<byte[]> responseList = Collections.emptyList();
            if (!checkClientTrusted && isExtSession) {
                responseList = ((ExtendedSSLSession) session).getStatusResponses();
            }
            trustedChain = validate(v, chain, responseList, constraints, checkClientTrusted ? null : authType);
            String identityAlg = sslSocket.getSSLParameters().getEndpointIdentificationAlgorithm();
            if (identityAlg != null && identityAlg.length() != 0) {
                checkIdentity(session, trustedChain, identityAlg, checkClientTrusted);
            }
        } else {
            trustedChain = validate(v, chain, Collections.emptyList(), null, checkClientTrusted ? null : authType);
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,trustmanager")) {
            SSLLogger.fine("Found trusted certificate", trustedChain[trustedChain.length - 1]);
        }
    }

    private void checkTrusted(X509Certificate[] chain, String authType, SSLEngine engine, boolean checkClientTrusted) throws CertificateException {
        X509Certificate[] trustedChain;
        AlgorithmConstraints constraints;
        Validator v = checkTrustedInit(chain, authType, checkClientTrusted);
        if (engine != null) {
            SSLSession session = engine.getHandshakeSession();
            if (session == null) {
                throw new CertificateException("No handshake session");
            }
            boolean isExtSession = session instanceof ExtendedSSLSession;
            if (isExtSession && ProtocolVersion.useTLS12PlusSpec(session.getProtocol())) {
                ExtendedSSLSession extSession = (ExtendedSSLSession) session;
                String[] localSupportedSignAlgs = extSession.getLocalSupportedSignatureAlgorithms();
                constraints = new SSLAlgorithmConstraints(engine, localSupportedSignAlgs, false);
            } else {
                constraints = new SSLAlgorithmConstraints(engine, false);
            }
            List<byte[]> responseList = Collections.emptyList();
            if (!checkClientTrusted && isExtSession) {
                responseList = ((ExtendedSSLSession) session).getStatusResponses();
            }
            trustedChain = validate(v, chain, responseList, constraints, checkClientTrusted ? null : authType);
            String identityAlg = engine.getSSLParameters().getEndpointIdentificationAlgorithm();
            if (identityAlg != null && identityAlg.length() != 0) {
                checkIdentity(session, trustedChain, identityAlg, checkClientTrusted);
            }
        } else {
            trustedChain = validate(v, chain, Collections.emptyList(), null, checkClientTrusted ? null : authType);
        }
        if (SSLLogger.isOn && SSLLogger.isOn("ssl,trustmanager")) {
            SSLLogger.fine("Found trusted certificate", trustedChain[trustedChain.length - 1]);
        }
    }

    private Validator getValidator(String variant) {
        Validator v;
        if (this.pkixParams == null) {
            v = Validator.getInstance(this.validatorType, variant, this.trustedCerts);
        } else {
            v = Validator.getInstance(this.validatorType, variant, this.pkixParams);
        }
        return v;
    }

    private static X509Certificate[] validate(Validator v, X509Certificate[] chain, List<byte[]> responseList, AlgorithmConstraints constraints, String authType) throws CertificateException {
        Object o = JsseJce.beginFipsProvider();
        try {
            X509Certificate[] validate = v.validate(chain, null, responseList, constraints, authType);
            JsseJce.endFipsProvider(o);
            return validate;
        } catch (Throwable th) {
            JsseJce.endFipsProvider(o);
            throw th;
        }
    }

    private static String getHostNameInSNI(List<SNIServerName> sniNames) {
        SNIHostName hostname = null;
        Iterator<SNIServerName> it = sniNames.iterator();
        while (true) {
            if (!it.hasNext()) {
                break;
            }
            SNIServerName sniName = it.next();
            if (sniName.getType() == 0) {
                if (sniName instanceof SNIHostName) {
                    hostname = (SNIHostName) sniName;
                } else {
                    try {
                        hostname = new SNIHostName(sniName.getEncoded());
                    } catch (IllegalArgumentException e) {
                        if (SSLLogger.isOn && SSLLogger.isOn("ssl,trustmanager")) {
                            SSLLogger.fine("Illegal server name: " + sniName, new Object[0]);
                        }
                    }
                }
            }
        }
        if (hostname != null) {
            return hostname.getAsciiName();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SNIServerName> getRequestedServerNames(Socket socket) {
        if (socket != null && socket.isConnected() && (socket instanceof SSLSocket)) {
            return getRequestedServerNames(((SSLSocket) socket).getHandshakeSession());
        }
        return Collections.emptyList();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static List<SNIServerName> getRequestedServerNames(SSLEngine engine) {
        if (engine != null) {
            return getRequestedServerNames(engine.getHandshakeSession());
        }
        return Collections.emptyList();
    }

    private static List<SNIServerName> getRequestedServerNames(SSLSession session) {
        if (session != null && (session instanceof ExtendedSSLSession)) {
            return ((ExtendedSSLSession) session).getRequestedServerNames();
        }
        return Collections.emptyList();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkIdentity(SSLSession session, X509Certificate[] trustedChain, String algorithm, boolean checkClientTrusted) throws CertificateException {
        boolean chainsToPublicCA = AnchorCertificates.contains(trustedChain[trustedChain.length - 1]);
        boolean identifiable = false;
        String peerHost = session.getPeerHost();
        if (!checkClientTrusted) {
            List<SNIServerName> sniNames = getRequestedServerNames(session);
            String sniHostName = getHostNameInSNI(sniNames);
            if (sniHostName != null) {
                try {
                    checkIdentity(sniHostName, trustedChain[0], algorithm, chainsToPublicCA);
                    identifiable = true;
                } catch (CertificateException ce) {
                    if (sniHostName.equalsIgnoreCase(peerHost)) {
                        throw ce;
                    }
                }
            }
        }
        if (!identifiable) {
            checkIdentity(peerHost, trustedChain[0], algorithm, chainsToPublicCA);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void checkIdentity(String hostname, X509Certificate cert, String algorithm) throws CertificateException {
        checkIdentity(hostname, cert, algorithm, false);
    }

    private static void checkIdentity(String hostname, X509Certificate cert, String algorithm, boolean chainsToPublicCA) throws CertificateException {
        if (algorithm != null && algorithm.length() != 0) {
            if (hostname != null && hostname.startsWith("[") && hostname.endsWith("]")) {
                hostname = hostname.substring(1, hostname.length() - 1);
            }
            if (algorithm.equalsIgnoreCase("HTTPS")) {
                HostnameChecker.getInstance((byte) 1).match(hostname, cert, chainsToPublicCA);
            } else if (algorithm.equalsIgnoreCase("LDAP") || algorithm.equalsIgnoreCase("LDAPS")) {
                HostnameChecker.getInstance((byte) 2).match(hostname, cert, chainsToPublicCA);
            } else {
                throw new CertificateException("Unknown identification algorithm: " + algorithm);
            }
        }
    }
}