package org.openjsse.com.sun.net.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/X509TrustManagerJavaxWrapper.class */
final class X509TrustManagerJavaxWrapper implements javax.net.ssl.X509TrustManager {
    private X509TrustManager theX509TrustManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509TrustManagerJavaxWrapper(X509TrustManager obj) {
        this.theX509TrustManager = obj;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (!this.theX509TrustManager.isClientTrusted(chain)) {
            throw new CertificateException("Untrusted Client Certificate Chain");
        }
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        if (!this.theX509TrustManager.isServerTrusted(chain)) {
            throw new CertificateException("Untrusted Server Certificate Chain");
        }
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return this.theX509TrustManager.getAcceptedIssuers();
    }
}