package org.bouncycastle.jsse.provider;

import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

/* loaded from: classes2.dex */
class ProvSSLSessionResumed extends ProvSSLSessionHandshake {
    protected final JsseSessionParameters jsseSessionParameters;
    protected final SessionParameters sessionParameters;
    protected final TlsSession tlsSession;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLSessionResumed(ProvSSLSessionContext provSSLSessionContext, String str, int i, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters, TlsSession tlsSession, JsseSessionParameters jsseSessionParameters) {
        super(provSSLSessionContext, str, i, securityParameters, jsseSecurityParameters);
        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected int getCipherSuiteTLS() {
        return this.sessionParameters.getCipherSuite();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected byte[] getIDArray() {
        return this.tlsSession.getSessionID();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected JsseSessionParameters getJsseSessionParameters() {
        return this.jsseSessionParameters;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getLocalCertificateTLS() {
        return this.sessionParameters.getLocalCertificate();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getPeerCertificateTLS() {
        return this.sessionParameters.getPeerCertificate();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected ProtocolVersion getProtocolTLS() {
        return this.sessionParameters.getNegotiatedVersion();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionHandshake, org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected void invalidateTLS() {
        this.tlsSession.invalidate();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase, javax.net.ssl.SSLSession
    public boolean isValid() {
        return super.isValid() && this.tlsSession.isResumable();
    }
}