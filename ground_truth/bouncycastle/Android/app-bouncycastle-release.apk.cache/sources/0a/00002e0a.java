package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsDH */
/* loaded from: classes2.dex */
public class BcTlsDH implements TlsAgreement {
    protected final BcTlsDHDomain domain;
    protected AsymmetricCipherKeyPair localKeyPair;
    protected DHPublicKeyParameters peerPublicKey;

    public BcTlsDH(BcTlsDHDomain bcTlsDHDomain) {
        this.domain = bcTlsDHDomain;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        return this.domain.calculateDHAgreement((DHPrivateKeyParameters) this.localKeyPair.getPrivate(), this.peerPublicKey);
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        AsymmetricCipherKeyPair generateKeyPair = this.domain.generateKeyPair();
        this.localKeyPair = generateKeyPair;
        return this.domain.encodePublicKey((DHPublicKeyParameters) generateKeyPair.getPublic());
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] bArr) throws IOException {
        this.peerPublicKey = this.domain.decodePublicKey(bArr);
    }
}