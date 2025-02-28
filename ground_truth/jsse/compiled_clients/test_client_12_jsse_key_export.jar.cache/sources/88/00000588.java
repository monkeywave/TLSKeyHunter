package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/RC2Parameters.class */
public class RC2Parameters extends KeyParameter {
    private int bits;

    public RC2Parameters(byte[] bArr) {
        this(bArr, bArr.length > 128 ? 1024 : bArr.length * 8);
    }

    public RC2Parameters(byte[] bArr, int i) {
        super(bArr);
        this.bits = i;
    }

    public int getEffectiveKeyBits() {
        return this.bits;
    }
}