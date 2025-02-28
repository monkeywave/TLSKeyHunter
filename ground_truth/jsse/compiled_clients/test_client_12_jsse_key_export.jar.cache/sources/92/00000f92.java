package org.openjsse.sun.security.provider.certpath.ssl;

import java.io.IOException;
import java.net.Socket;
import java.net.URI;
import java.net.URLConnection;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.Provider;
import java.security.cert.CRLSelector;
import java.security.cert.CertSelector;
import java.security.cert.CertStore;
import java.security.cert.CertStoreException;
import java.security.cert.CertStoreParameters;
import java.security.cert.CertStoreSpi;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/certpath/ssl/SSLServerCertStore.class */
public final class SSLServerCertStore extends CertStoreSpi {
    private final URI uri;
    private static final SSLSocketFactory socketFactory;
    private static final GetChainTrustManager trustManager = new GetChainTrustManager();
    private static final HostnameVerifier hostnameVerifier = new HostnameVerifier() { // from class: org.openjsse.sun.security.provider.certpath.ssl.SSLServerCertStore.1
        @Override // javax.net.ssl.HostnameVerifier
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    static {
        SSLSocketFactory tempFactory;
        try {
            SSLContext context = SSLContext.getInstance("SSL");
            context.init(null, new TrustManager[]{trustManager}, null);
            tempFactory = context.getSocketFactory();
        } catch (GeneralSecurityException e) {
            tempFactory = null;
        }
        socketFactory = tempFactory;
    }

    SSLServerCertStore(URI uri) throws InvalidAlgorithmParameterException {
        super(null);
        this.uri = uri;
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection<X509Certificate> engineGetCertificates(CertSelector selector) throws CertStoreException {
        List<X509Certificate> matchingCerts;
        try {
            URLConnection urlConn = this.uri.toURL().openConnection();
            if (urlConn instanceof HttpsURLConnection) {
                if (socketFactory == null) {
                    throw new CertStoreException("No initialized SSLSocketFactory");
                }
                HttpsURLConnection https = (HttpsURLConnection) urlConn;
                https.setSSLSocketFactory(socketFactory);
                https.setHostnameVerifier(hostnameVerifier);
                synchronized (trustManager) {
                    try {
                        try {
                            https.connect();
                            matchingCerts = getMatchingCerts(trustManager.serverChain, selector);
                            trustManager.cleanup();
                        } catch (IOException ioe) {
                            if (trustManager.exchangedServerCerts) {
                                List<X509Certificate> matchingCerts2 = getMatchingCerts(trustManager.serverChain, selector);
                                trustManager.cleanup();
                                return matchingCerts2;
                            }
                            throw ioe;
                        }
                    } catch (Throwable th) {
                        trustManager.cleanup();
                        throw th;
                    }
                }
                return matchingCerts;
            }
            return Collections.emptySet();
        } catch (IOException ioe2) {
            throw new CertStoreException(ioe2);
        }
    }

    private static List<X509Certificate> getMatchingCerts(List<X509Certificate> certs, CertSelector selector) {
        if (selector == null) {
            return certs;
        }
        List<X509Certificate> matchedCerts = new ArrayList<>(certs.size());
        for (X509Certificate cert : certs) {
            if (selector.match(cert)) {
                matchedCerts.add(cert);
            }
        }
        return matchedCerts;
    }

    @Override // java.security.cert.CertStoreSpi
    public Collection<X509CRL> engineGetCRLs(CRLSelector selector) throws CertStoreException {
        throw new UnsupportedOperationException();
    }

    public static CertStore getInstance(URI uri) throws InvalidAlgorithmParameterException {
        return new C0356CS(new SSLServerCertStore(uri), null, "SSLServer", null);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/certpath/ssl/SSLServerCertStore$GetChainTrustManager.class */
    private static class GetChainTrustManager extends X509ExtendedTrustManager {
        private List<X509Certificate> serverChain;
        private boolean exchangedServerCerts;

        private GetChainTrustManager() {
            this.serverChain = Collections.emptyList();
            this.exchangedServerCerts = false;
        }

        @Override // javax.net.ssl.X509TrustManager
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

        @Override // javax.net.ssl.X509TrustManager
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override // javax.net.ssl.X509ExtendedTrustManager
        public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override // javax.net.ssl.X509ExtendedTrustManager
        public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            throw new UnsupportedOperationException();
        }

        @Override // javax.net.ssl.X509TrustManager
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            List<X509Certificate> asList;
            this.exchangedServerCerts = true;
            if (chain == null) {
                asList = Collections.emptyList();
            } else {
                asList = Arrays.asList(chain);
            }
            this.serverChain = asList;
        }

        @Override // javax.net.ssl.X509ExtendedTrustManager
        public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        @Override // javax.net.ssl.X509ExtendedTrustManager
        public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine) throws CertificateException {
            checkServerTrusted(chain, authType);
        }

        void cleanup() {
            this.exchangedServerCerts = false;
            this.serverChain = Collections.emptyList();
        }
    }

    /* renamed from: org.openjsse.sun.security.provider.certpath.ssl.SSLServerCertStore$CS */
    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/certpath/ssl/SSLServerCertStore$CS.class */
    private static class C0356CS extends CertStore {
        protected C0356CS(CertStoreSpi spi, Provider p, String type, CertStoreParameters params) {
            super(spi, p, type, params);
        }
    }
}