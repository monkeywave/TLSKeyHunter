package org.openjsse.com.sun.net.ssl;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.cert.Certificate;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSocketFactory;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/HttpsURLConnection.class */
public abstract class HttpsURLConnection extends HttpURLConnection {
    protected HostnameVerifier hostnameVerifier;
    private SSLSocketFactory sslSocketFactory;
    private static HostnameVerifier defaultHostnameVerifier = new HostnameVerifier() { // from class: org.openjsse.com.sun.net.ssl.HttpsURLConnection.1
        @Override // org.openjsse.com.sun.net.ssl.HostnameVerifier
        public boolean verify(String urlHostname, String certHostname) {
            return false;
        }
    };
    private static SSLSocketFactory defaultSSLSocketFactory = null;

    public abstract String getCipherSuite();

    public abstract Certificate[] getServerCertificates() throws SSLPeerUnverifiedException;

    public HttpsURLConnection(URL url) throws IOException {
        super(url);
        this.hostnameVerifier = defaultHostnameVerifier;
        this.sslSocketFactory = getDefaultSSLSocketFactory();
    }

    public static void setDefaultHostnameVerifier(HostnameVerifier v) {
        if (v == null) {
            throw new IllegalArgumentException("no default HostnameVerifier specified");
        }
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkPermission(new SSLPermission("setHostnameVerifier"));
        }
        defaultHostnameVerifier = v;
    }

    public static HostnameVerifier getDefaultHostnameVerifier() {
        return defaultHostnameVerifier;
    }

    public void setHostnameVerifier(HostnameVerifier v) {
        if (v == null) {
            throw new IllegalArgumentException("no HostnameVerifier specified");
        }
        this.hostnameVerifier = v;
    }

    public HostnameVerifier getHostnameVerifier() {
        return this.hostnameVerifier;
    }

    public static void setDefaultSSLSocketFactory(SSLSocketFactory sf) {
        if (sf == null) {
            throw new IllegalArgumentException("no default SSLSocketFactory specified");
        }
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkSetFactory();
        }
        defaultSSLSocketFactory = sf;
    }

    public static SSLSocketFactory getDefaultSSLSocketFactory() {
        if (defaultSSLSocketFactory == null) {
            defaultSSLSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        }
        return defaultSSLSocketFactory;
    }

    public void setSSLSocketFactory(SSLSocketFactory sf) {
        if (sf == null) {
            throw new IllegalArgumentException("no SSLSocketFactory specified");
        }
        SecurityManager sm = System.getSecurityManager();
        if (sm != null) {
            sm.checkSetFactory();
        }
        this.sslSocketFactory = sf;
    }

    public SSLSocketFactory getSSLSocketFactory() {
        return this.sslSocketFactory;
    }
}