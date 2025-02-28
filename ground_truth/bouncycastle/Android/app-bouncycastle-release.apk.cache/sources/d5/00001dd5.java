package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.crypto.params.Blake3Parameters;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: classes2.dex */
public class Blake3Mac implements Mac {
    private final Blake3Digest theDigest;

    public Blake3Mac(Blake3Digest blake3Digest) {
        this.theDigest = blake3Digest;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) {
        return this.theDigest.doFinal(bArr, i);
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return this.theDigest.getAlgorithmName() + "Mac";
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return this.theDigest.getDigestSize();
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) {
        CipherParameters key = cipherParameters instanceof KeyParameter ? Blake3Parameters.key(((KeyParameter) cipherParameters).getKey()) : cipherParameters;
        if (!(key instanceof Blake3Parameters)) {
            throw new IllegalArgumentException("Invalid parameter passed to Blake3Mac init - " + cipherParameters.getClass().getName());
        }
        Blake3Parameters blake3Parameters = (Blake3Parameters) key;
        if (blake3Parameters.getKey() == null) {
            throw new IllegalArgumentException("Blake3Mac requires a key parameter.");
        }
        this.theDigest.init(blake3Parameters);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        this.theDigest.reset();
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) {
        this.theDigest.update(b);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) {
        this.theDigest.update(bArr, i, i2);
    }
}