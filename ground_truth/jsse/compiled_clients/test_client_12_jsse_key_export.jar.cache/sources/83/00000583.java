package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ParametersWithIV.class */
public class ParametersWithIV implements CipherParameters {

    /* renamed from: iv */
    private byte[] f558iv;
    private CipherParameters parameters;

    public ParametersWithIV(CipherParameters cipherParameters, byte[] bArr) {
        this(cipherParameters, bArr, 0, bArr.length);
    }

    public ParametersWithIV(CipherParameters cipherParameters, byte[] bArr, int i, int i2) {
        this.f558iv = new byte[i2];
        this.parameters = cipherParameters;
        System.arraycopy(bArr, i, this.f558iv, 0, i2);
    }

    public byte[] getIV() {
        return this.f558iv;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}