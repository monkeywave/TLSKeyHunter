package org.bouncycastle.jsse.provider;

import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import org.bouncycastle.jsse.BCX509ExtendedTrustManager;

/* loaded from: classes2.dex */
class ExportX509TrustManager_7 extends X509ExtendedTrustManager implements ExportX509TrustManager {
    final BCX509ExtendedTrustManager x509TrustManager;

    ExportX509TrustManager_7(BCX509ExtendedTrustManager bCX509ExtendedTrustManager) {
        this.x509TrustManager = bCX509ExtendedTrustManager;
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str, socket);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkClientTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        this.x509TrustManager.checkClientTrusted(x509CertificateArr, str, sSLEngine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, Socket socket) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str, socket);
    }

    @Override // javax.net.ssl.X509ExtendedTrustManager
    public void checkServerTrusted(X509Certificate[] x509CertificateArr, String str, SSLEngine sSLEngine) throws CertificateException {
        this.x509TrustManager.checkServerTrusted(x509CertificateArr, str, sSLEngine);
    }

    @Override // javax.net.ssl.X509TrustManager
    public X509Certificate[] getAcceptedIssuers() {
        return this.x509TrustManager.getAcceptedIssuers();
    }

    @Override // org.bouncycastle.jsse.provider.ExportX509TrustManager
    public BCX509ExtendedTrustManager unwrap() {
        return this.x509TrustManager;
    }
}