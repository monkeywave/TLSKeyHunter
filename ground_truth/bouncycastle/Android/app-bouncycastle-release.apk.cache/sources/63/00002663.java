package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public final class DummyX509TrustManager extends BCX509ExtendedTrustManager {
    static final BCX509ExtendedTrustManager INSTANCE = new DummyX509TrustManager();

    private DummyX509TrustManager() {
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        throw new CertificateException("No X509TrustManager implementation available");
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return JsseUtils.EMPTY_X509CERTIFICATES;
    }
}