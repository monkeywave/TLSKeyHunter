package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/IESWithCipherParameters.class */
public class IESWithCipherParameters extends IESParameters {
    private int cipherKeySize;

    public IESWithCipherParameters(byte[] bArr, byte[] bArr2, int i, int i2) {
        super(bArr, bArr2, i);
        this.cipherKeySize = i2;
    }

    public int getCipherKeySize() {
        return this.cipherKeySize;
    }
}