package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

/* loaded from: classes2.dex */
class ImportX509TrustManager_7 extends BCX509ExtendedTrustManager implements ImportX509TrustManager {
    final X509ExtendedTrustManager x509TrustManager;

    ImportX509TrustManager_7(X509ExtendedTrustManager x509ExtendedTrustManager) {
        this.x509TrustManager = x509ExtendedTrustManager;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str, socket);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str, sSLEngine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str, socket);
    }

    @Override // org.bouncycastle.jsse.BCX509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str, sSLEngine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }

    @Override // org.bouncycastle.jsse.provider.ImportX509TrustManager
    public X509TrustManager unwrap() {
        return this.x509TrustManager;
    }
}