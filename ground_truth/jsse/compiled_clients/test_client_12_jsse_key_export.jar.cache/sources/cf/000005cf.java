package org.bouncycastle.crypto.signers;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.math.p010ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/signers/Ed448phSigner.class */
public class Ed448phSigner implements Signer {
    private final Xof prehash = Ed448.createPrehash();
    private final byte[] context;
    private boolean forSigning;
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448phSigner(byte[] bArr) {
        this.context = Arrays.clone(bArr);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forSigning = z;
        if (z) {
            this.privateKey = (Ed448PrivateKeyParameters) cipherParameters;
            this.publicKey = null;
        } else {
            this.privateKey = null;
            this.publicKey = (Ed448PublicKeyParameters) cipherParameters;
        }
        reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte b) {
        this.prehash.update(b);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void update(byte[] bArr, int i, int i2) {
        this.prehash.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() {
        if (!this.forSigning || null == this.privateKey) {
            throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
        }
        byte[] bArr = new byte[64];
        if (64 != this.prehash.doFinal(bArr, 0, 64)) {
            throw new IllegalStateException("Prehash digest failed");
        }
        byte[] bArr2 = new byte[114];
        this.privateKey.sign(1, this.context, bArr, 0, 64, bArr2, 0);
        return bArr2;
    }

    @Override // org.bouncycastle.crypto.Signer
    public boolean verifySignature(byte[] bArr) {
        if (this.forSigning || null == this.publicKey) {
            throw new IllegalStateException("Ed448phSigner not initialised for verification");
        }
        if (114 != bArr.length) {
            this.prehash.reset();
            return false;
        }
        return Ed448.verifyPrehash(bArr, 0, this.publicKey.getEncoded(), 0, this.context, this.prehash);
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.prehash.reset();
    }
}