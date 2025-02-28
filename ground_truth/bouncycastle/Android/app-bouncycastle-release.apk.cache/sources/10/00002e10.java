package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsECDH */
/* loaded from: classes2.dex */
public class BcTlsECDH implements TlsAgreement {
    protected final BcTlsECDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected ECPublicKeyParameters peerPublicKey;

    public BcTlsECDH(BcTlsECDomain bcTlsECDomain) {
        this.domain = bcTlsECDomain;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        return this.domain.calculateECDHAgreement((ECPrivateKeyParameters) this.localKeyPair.getPrivate(), this.peerPublicKey);
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        AsymmetricCipherKeyPair generateKeyPair = this.domain.generateKeyPair();
        this.localKeyPair = generateKeyPair;
        return this.domain.encodePublicKey((ECPublicKeyParameters) generateKeyPair.getPublic());
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] bArr) throws IOException {
        this.peerPublicKey = this.domain.decodePublicKey(bArr);
    }
}