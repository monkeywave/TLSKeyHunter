package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class GeMSSPublicKeyParameters extends GeMSSKeyParameters {

    /* renamed from: pk */
    private final byte[] f1272pk;

    public GeMSSPublicKeyParameters(GeMSSParameters geMSSParameters, byte[] bArr) {
        super(false, geMSSParameters);
        byte[] bArr2 = new byte[bArr.length];
        this.f1272pk = bArr2;
        System.arraycopy(bArr, 0, bArr2, 0, bArr2.length);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.f1272pk);
    }

    public byte[] getPK() {
        return this.f1272pk;
    }
}