package org.bouncycastle.jsse.provider;

import java.security.Principal;
import java.security.cert.Certificate;
import javax.net.ssl.ExtendedSSLSession;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSessionContext;
import javax.security.cert.X509Certificate;
import org.bouncycastle.jsse.BCExtendedSSLSession;

/* loaded from: classes2.dex */
class ExportSSLSession_7 extends ExtendedSSLSession implements ExportSSLSession {
    final BCExtendedSSLSession sslSession;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ExportSSLSession_7(BCExtendedSSLSession bCExtendedSSLSession) {
        this.sslSession = bCExtendedSSLSession;
    }

    public boolean equals(Object obj) {
        return obj != null && obj.equals(this.sslSession);
    }

    @Override // javax.net.ssl.SSLSession
    public int getApplicationBufferSize() {
        return this.sslSession.getApplicationBufferSize();
    }

    @Override // javax.net.ssl.SSLSession
    public String getCipherSuite() {
        return this.sslSession.getCipherSuite();
    }

    @Override // javax.net.ssl.SSLSession
    public long getCreationTime() {
        return this.sslSession.getCreationTime();
    }

    @Override // javax.net.ssl.SSLSession
    public byte[] getId() {
        return this.sslSession.getId();
    }

    @Override // javax.net.ssl.SSLSession
    public long getLastAccessedTime() {
        return this.sslSession.getLastAccessedTime();
    }

    @Override // javax.net.ssl.SSLSession
    public Certificate[] getLocalCertificates() {
        return this.sslSession.getLocalCertificates();
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getLocalPrincipal() {
        return this.sslSession.getLocalPrincipal();
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return this.sslSession.getLocalSupportedSignatureAlgorithms();
    }

    @Override // javax.net.ssl.SSLSession
    public int getPacketBufferSize() {
        return this.sslSession.getPacketBufferSize();
    }

    @Override // javax.net.ssl.SSLSession
    public X509Certificate[] getPeerCertificateChain() throws SSLPeerUnverifiedException {
        return OldCertUtil.getPeerCertificateChain(this.sslSession);
    }

    @Override // javax.net.ssl.SSLSession
    public Certificate[] getPeerCertificates() throws SSLPeerUnverifiedException {
        return this.sslSession.getPeerCertificates();
    }

    @Override // javax.net.ssl.SSLSession
    public String getPeerHost() {
        return this.sslSession.getPeerHost();
    }

    @Override // javax.net.ssl.SSLSession
    public int getPeerPort() {
        return this.sslSession.getPeerPort();
    }

    @Override // javax.net.ssl.SSLSession
    public Principal getPeerPrincipal() throws SSLPeerUnverifiedException {
        return this.sslSession.getPeerPrincipal();
    }

    @Override // javax.net.ssl.ExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        return this.sslSession.getPeerSupportedSignatureAlgorithms();
    }

    @Override // javax.net.ssl.SSLSession
    public String getProtocol() {
        return this.sslSession.getProtocol();
    }

    @Override // javax.net.ssl.SSLSession
    public SSLSessionContext getSessionContext() {
        return this.sslSession.getSessionContext();
    }

    @Override // javax.net.ssl.SSLSession
    public Object getValue(String str) {
        return this.sslSession.getValue(str);
    }

    @Override // javax.net.ssl.SSLSession
    public String[] getValueNames() {
        return this.sslSession.getValueNames();
    }

    public int hashCode() {
        return this.sslSession.hashCode();
    }

    @Override // javax.net.ssl.SSLSession
    public void invalidate() {
        this.sslSession.invalidate();
    }

    @Override // javax.net.ssl.SSLSession
    public boolean isValid() {
        return this.sslSession.isValid();
    }

    @Override // javax.net.ssl.SSLSession
    public void putValue(String str, Object obj) {
        this.sslSession.putValue(str, obj);
    }

    @Override // javax.net.ssl.SSLSession
    public void removeValue(String str) {
        this.sslSession.removeValue(str);
    }

    public String toString() {
        return this.sslSession.toString();
    }

    @Override // org.bouncycastle.jsse.provider.ExportSSLSession
    public BCExtendedSSLSession unwrap() {
        return this.sslSession;
    }
}