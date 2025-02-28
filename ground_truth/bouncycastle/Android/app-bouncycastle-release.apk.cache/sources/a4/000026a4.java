package org.bouncycastle.jsse.provider;

import java.util.List;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SessionParameters;
import org.bouncycastle.tls.TlsSession;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLSession extends ProvSSLSessionBase {
    static final ProvSSLSession NULL_SESSION = new ProvSSLSession(null, null, -1, null, new JsseSessionParameters(null, null));
    protected final JsseSessionParameters jsseSessionParameters;
    protected final SessionParameters sessionParameters;
    protected final TlsSession tlsSession;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLSession(ProvSSLSessionContext provSSLSessionContext, String str, int i, TlsSession tlsSession, JsseSessionParameters jsseSessionParameters) {
        super(provSSLSessionContext, str, i);
        this.tlsSession = tlsSession;
        this.sessionParameters = tlsSession == null ? null : tlsSession.exportSessionParameters();
        this.jsseSessionParameters = jsseSessionParameters;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected int getCipherSuiteTLS() {
        SessionParameters sessionParameters = this.sessionParameters;
        if (sessionParameters == null) {
            return 0;
        }
        return sessionParameters.getCipherSuite();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected byte[] getIDArray() {
        TlsSession tlsSession = this.tlsSession;
        if (tlsSession == null) {
            return null;
        }
        return tlsSession.getSessionID();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected JsseSecurityParameters getJsseSecurityParameters() {
        return null;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    public JsseSessionParameters getJsseSessionParameters() {
        return this.jsseSessionParameters;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getLocalCertificateTLS() {
        SessionParameters sessionParameters = this.sessionParameters;
        if (sessionParameters == null) {
            return null;
        }
        return sessionParameters.getLocalCertificate();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return null;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getPeerCertificateTLS() {
        SessionParameters sessionParameters = this.sessionParameters;
        if (sessionParameters == null) {
            return null;
        }
        return sessionParameters.getPeerCertificate();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        return null;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected ProtocolVersion getProtocolTLS() {
        SessionParameters sessionParameters = this.sessionParameters;
        if (sessionParameters == null) {
            return null;
        }
        return sessionParameters.getNegotiatedVersion();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public List<BCSNIServerName> getRequestedServerNames() {
        throw new UnsupportedOperationException();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsSession getTlsSession() {
        return this.tlsSession;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected void invalidateTLS() {
        TlsSession tlsSession = this.tlsSession;
        if (tlsSession != null) {
            tlsSession.invalidate();
        }
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase, javax.net.ssl.SSLSession
    public boolean isValid() {
        TlsSession tlsSession;
        return super.isValid() && (tlsSession = this.tlsSession) != null && tlsSession.isResumable();
    }
}