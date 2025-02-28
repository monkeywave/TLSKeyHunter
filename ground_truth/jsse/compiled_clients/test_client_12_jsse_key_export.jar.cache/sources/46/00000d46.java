package org.bouncycastle.pqc.crypto.gmss;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.StateAwareMessageSigner;
import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/GMSSStateAwareSigner.class */
public class GMSSStateAwareSigner implements StateAwareMessageSigner {
    private final GMSSSigner gmssSigner;
    private GMSSPrivateKeyParameters key;

    public GMSSStateAwareSigner(Digest digest) {
        if (!(digest instanceof Memoable)) {
            throw new IllegalArgumentException("digest must implement Memoable");
        }
        final Memoable copy = ((Memoable) digest).copy();
        this.gmssSigner = new GMSSSigner(new GMSSDigestProvider() { // from class: org.bouncycastle.pqc.crypto.gmss.GMSSStateAwareSigner.1
            @Override // org.bouncycastle.pqc.crypto.gmss.GMSSDigestProvider
            public Digest get() {
                return (Digest) copy.copy();
            }
        });
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        if (z) {
            if (cipherParameters instanceof ParametersWithRandom) {
                this.key = (GMSSPrivateKeyParameters) ((ParametersWithRandom) cipherParameters).getParameters();
            } else {
                this.key = (GMSSPrivateKeyParameters) cipherParameters;
            }
        }
        this.gmssSigner.init(z, cipherParameters);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        if (this.key == null) {
            throw new IllegalStateException("signing key no longer usable");
        }
        byte[] generateSignature = this.gmssSigner.generateSignature(bArr);
        this.key = this.key.nextKey();
        return generateSignature;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        return this.gmssSigner.verifySignature(bArr, bArr2);
    }

    @Override // org.bouncycastle.pqc.crypto.StateAwareMessageSigner
    public AsymmetricKeyParameter getUpdatedPrivateKey() {
        GMSSPrivateKeyParameters gMSSPrivateKeyParameters = this.key;
        this.key = null;
        return gMSSPrivateKeyParameters;
    }
}