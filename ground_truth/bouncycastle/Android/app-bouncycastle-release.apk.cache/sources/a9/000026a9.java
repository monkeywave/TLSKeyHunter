package org.bouncycastle.jsse.provider;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import org.bouncycastle.jsse.BCSNIServerName;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.ProtocolVersion;
import org.bouncycastle.tls.SecurityParameters;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class ProvSSLSessionHandshake extends ProvSSLSessionBase {
    protected final JsseSecurityParameters jsseSecurityParameters;
    protected final SecurityParameters securityParameters;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ProvSSLSessionHandshake(ProvSSLSessionContext provSSLSessionContext, String str, int i, SecurityParameters securityParameters, JsseSecurityParameters jsseSecurityParameters) {
        super(provSSLSessionContext, str, i);
        this.securityParameters = securityParameters;
        this.jsseSecurityParameters = jsseSecurityParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public String getApplicationProtocol() {
        return JsseUtils.getApplicationProtocol(this.securityParameters);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected int getCipherSuiteTLS() {
        return this.securityParameters.getCipherSuite();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected byte[] getIDArray() {
        return this.securityParameters.getSessionID();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    public JsseSecurityParameters getJsseSecurityParameters() {
        return this.jsseSecurityParameters;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected JsseSessionParameters getJsseSessionParameters() {
        return null;
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getLocalCertificateTLS() {
        return this.securityParameters.getLocalCertificate();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithms() {
        return this.jsseSecurityParameters.signatureSchemes.getLocalJcaSignatureAlgorithms();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getLocalSupportedSignatureAlgorithmsBC() {
        return this.jsseSecurityParameters.signatureSchemes.getLocalJcaSignatureAlgorithmsBC();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected Certificate getPeerCertificateTLS() {
        return this.securityParameters.getPeerCertificate();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithms() {
        return this.jsseSecurityParameters.signatureSchemes.getPeerJcaSignatureAlgorithms();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public String[] getPeerSupportedSignatureAlgorithmsBC() {
        return this.jsseSecurityParameters.signatureSchemes.getPeerJcaSignatureAlgorithmsBC();
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected ProtocolVersion getProtocolTLS() {
        return this.securityParameters.getNegotiatedVersion();
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public List<BCSNIServerName> getRequestedServerNames() {
        return JsseUtils.convertSNIServerNames(this.securityParameters.getClientServerNames());
    }

    @Override // org.bouncycastle.jsse.BCExtendedSSLSession
    public List<byte[]> getStatusResponses() {
        List<byte[]> list = this.jsseSecurityParameters.statusResponses;
        if (list == null || list.isEmpty()) {
            return Collections.emptyList();
        }
        ArrayList arrayList = new ArrayList(list.size());
        for (byte[] bArr : list) {
            arrayList.add(bArr.clone());
        }
        return Collections.unmodifiableList(arrayList);
    }

    @Override // org.bouncycastle.jsse.provider.ProvSSLSessionBase
    protected void invalidateTLS() {
    }
}