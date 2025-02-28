package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class ParametersWithContext implements CipherParameters {
    private byte[] context;
    private CipherParameters parameters;

    public ParametersWithContext(CipherParameters cipherParameters, byte[] bArr) {
        if (bArr == null) {
            throw new NullPointerException("'context' cannot be null");
        }
        this.parameters = cipherParameters;
        this.context = Arrays.clone(bArr);
    }

    public void copyContextTo(byte[] bArr, int i, int i2) {
        byte[] bArr2 = this.context;
        if (bArr2.length != i2) {
            throw new IllegalArgumentException("len");
        }
        System.arraycopy(bArr2, 0, bArr, i, i2);
    }

    public byte[] getContext() {
        return Arrays.clone(this.context);
    }

    public int getContextLength() {
        return this.context.length;
    }

    public CipherParameters getParameters() {
        return this.parameters;
    }
}