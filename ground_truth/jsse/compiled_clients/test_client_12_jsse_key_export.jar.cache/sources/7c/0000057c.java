package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/MGFParameters.class */
public class MGFParameters implements DerivationParameters {
    byte[] seed;

    public MGFParameters(byte[] bArr) {
        this(bArr, 0, bArr.length);
    }

    public MGFParameters(byte[] bArr, int i, int i2) {
        this.seed = new byte[i2];
        System.arraycopy(bArr, i, this.seed, 0, i2);
    }

    public byte[] getSeed() {
        return this.seed;
    }
}