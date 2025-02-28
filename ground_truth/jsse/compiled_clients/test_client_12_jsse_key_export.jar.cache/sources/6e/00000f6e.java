package org.openjsse.com.sun.net.ssl.internal.ssl;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.X509TrustManager;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/internal/ssl/X509ExtendedTrustManager.class */
public abstract class X509ExtendedTrustManager implements X509TrustManager {
    public abstract void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, String str2, String str3) throws CertificateException;

    public abstract void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, String str2, String str3) throws CertificateException;

    protected X509ExtendedTrustManager() {
    }
}