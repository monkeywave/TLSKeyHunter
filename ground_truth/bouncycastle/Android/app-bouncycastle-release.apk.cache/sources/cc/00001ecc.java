package org.bouncycastle.crypto.signers;

import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PublicKeyParameters;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.math.p016ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class Ed448phSigner implements Signer {
    private final byte[] context;
    private boolean forSigning;
    private final Xof prehash = Ed448.createPrehash();
    private Ed448PrivateKeyParameters privateKey;
    private Ed448PublicKeyParameters publicKey;

    public Ed448phSigner(byte[] bArr) {
        if (bArr == null) {
            throw new NullPointerException("'context' cannot be null");
        }
        this.context = Arrays.clone(bArr);
    }

    @Override // org.bouncycastle.crypto.Signer
    public byte[] generateSignature() {
        if (!this.forSigning || this.privateKey == null) {
            throw new IllegalStateException("Ed448phSigner not initialised for signature generation.");
        }
        byte[] bArr = new byte[64];
        if (64 == this.prehash.doFinal(bArr, 0, 64)) {
            byte[] bArr2 = new byte[114];
            this.privateKey.sign(1, this.context, bArr, 0, 64, bArr2, 0);
            return bArr2;
        }
        throw new IllegalStateException("Prehash digest failed");
    }

    @Override // org.bouncycastle.crypto.Signer
    public void init(boolean z, CipherParameters cipherParameters) {
        this.forSigning = z;
        Ed448PublicKeyParameters ed448PublicKeyParameters = null;
        if (z) {
            this.privateKey = (Ed448PrivateKeyParameters) cipherParameters;
        } else {
            this.privateKey = null;
            ed448PublicKeyParameters = (Ed448PublicKeyParameters) cipherParameters;
        }
        this.publicKey = ed448PublicKeyParameters;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(EdDSAParameterSpec.Ed448, BERTags.FLAGS, cipherParameters, z));
        reset();
    }

    @Override // org.bouncycastle.crypto.Signer
    public void reset() {
        this.prehash.reset();
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
    public boolean verifySignature(byte[] bArr) {
        if (this.forSigning || this.publicKey == null) {
            throw new IllegalStateException("Ed448phSigner not initialised for verification");
        }
        if (114 != bArr.length) {
            this.prehash.reset();
            return false;
        }
        byte[] bArr2 = new byte[64];
        if (64 == this.prehash.doFinal(bArr2, 0, 64)) {
            return this.publicKey.verify(1, this.context, bArr2, 0, 64, bArr, 0);
        }
        throw new IllegalStateException("Prehash digest failed");
    }
}