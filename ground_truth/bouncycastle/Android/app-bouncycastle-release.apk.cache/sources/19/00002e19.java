package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsSecret;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsMLKem */
/* loaded from: classes2.dex */
public class BcTlsMLKem implements TlsAgreement {
    protected final BcTlsMLKemDomain domain;
    protected MLKEMPrivateKeyParameters privateKey;
    protected MLKEMPublicKeyParameters publicKey;
    protected TlsSecret secret;

    public BcTlsMLKem(BcTlsMLKemDomain bcTlsMLKemDomain) {
        this.domain = bcTlsMLKemDomain;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public TlsSecret calculateSecret() throws IOException {
        TlsSecret tlsSecret = this.secret;
        this.secret = null;
        return tlsSecret;
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public byte[] generateEphemeral() throws IOException {
        if (!this.domain.isServer()) {
            AsymmetricCipherKeyPair generateKeyPair = this.domain.generateKeyPair();
            this.privateKey = (MLKEMPrivateKeyParameters) generateKeyPair.getPrivate();
            return this.domain.encodePublicKey((MLKEMPublicKeyParameters) generateKeyPair.getPublic());
        }
        SecretWithEncapsulation encapsulate = this.domain.encapsulate(this.publicKey);
        this.publicKey = null;
        this.secret = this.domain.adoptLocalSecret(encapsulate.getSecret());
        return encapsulate.getEncapsulation();
    }

    @Override // org.bouncycastle.tls.crypto.TlsAgreement
    public void receivePeerValue(byte[] bArr) throws IOException {
        if (this.domain.isServer()) {
            this.publicKey = this.domain.decodePublicKey(bArr);
            return;
        }
        this.secret = this.domain.decapsulate(this.privateKey, bArr);
        this.privateKey = null;
    }
}