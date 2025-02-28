package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public class JceX25519 implements TlsAgreement {
    protected final JceX25519Domain domain;
    protected KeyPair localKeyPair;
    protected PublicKey peerPublicKey;

    public JceX25519(JceX25519Domain jceX25519Domain) {
        this.domain = jceX25519Domain;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        return this.domain.calculateECDHAgreement(this.localKeyPair.getPrivate(), this.peerPublicKey);
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        KeyPair generateKeyPair = this.domain.generateKeyPair();
        this.localKeyPair = generateKeyPair;
        return this.domain.encodePublicKey(generateKeyPair.getPublic());
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] bArr) throws IOException {
        this.peerPublicKey = this.domain.decodePublicKey(bArr);
    }
}