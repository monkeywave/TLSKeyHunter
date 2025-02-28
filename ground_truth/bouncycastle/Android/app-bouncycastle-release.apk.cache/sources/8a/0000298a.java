package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class FalconPrivateKeyParameters extends FalconKeyParameters {

    /* renamed from: F */
    private final byte[] f1234F;

    /* renamed from: f */
    private final byte[] f1235f;

    /* renamed from: g */
    private final byte[] f1236g;

    /* renamed from: pk */
    private final byte[] f1237pk;

    public FalconPrivateKeyParameters(FalconParameters falconParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        super(true, falconParameters);
        this.f1235f = Arrays.clone(bArr);
        this.f1236g = Arrays.clone(bArr2);
        this.f1234F = Arrays.clone(bArr3);
        this.f1237pk = Arrays.clone(bArr4);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f1235f, this.f1236g, this.f1234F);
    }

    public byte[] getG() {
        return Arrays.clone(this.f1236g);
    }

    public byte[] getPublicKey() {
        return Arrays.clone(this.f1237pk);
    }

    public byte[] getSpolyF() {
        return Arrays.clone(this.f1234F);
    }

    public byte[] getSpolyf() {
        return Arrays.clone(this.f1235f);
    }
}