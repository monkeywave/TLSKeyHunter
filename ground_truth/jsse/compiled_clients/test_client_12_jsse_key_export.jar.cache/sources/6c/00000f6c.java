package org.openjsse.com.sun.net.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/* compiled from: SSLSecurity.java */
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/X509TrustManagerComSunWrapper.class */
final class X509TrustManagerComSunWrapper implements X509TrustManager {
    private javax.net.ssl.X509TrustManager theX509TrustManager;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X509TrustManagerComSunWrapper(javax.net.ssl.X509TrustManager obj) {
        this.theX509TrustManager = obj;
    }

    @Override // org.openjsse.com.sun.net.ssl.X509TrustManager
    public boolean isClientTrusted(X509Certificate[] chain) {
        try {
            this.theX509TrustManager.checkClientTrusted(chain, "UNKNOWN");
            return true;
        } catch (CertificateException e) {
            return false;
        }
    }

    @Override // org.openjsse.com.sun.net.ssl.X509TrustManager
    public boolean isServerTrusted(X509Certificate[] chain) {
        try {
            this.theX509TrustManager.checkServerTrusted(chain, "UNKNOWN");
            return true;
        } catch (CertificateException e) {
            return false;
        }
    }

    @Override // org.openjsse.com.sun.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return this.theX509TrustManager.getAcceptedIssuers();
    }
}