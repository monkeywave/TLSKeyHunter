package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class BIKEPrivateKeyParameters extends BIKEKeyParameters {

    /* renamed from: h0 */
    private byte[] f1215h0;

    /* renamed from: h1 */
    private byte[] f1216h1;
    private byte[] sigma;

    public BIKEPrivateKeyParameters(BIKEParameters bIKEParameters, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        super(true, bIKEParameters);
        this.f1215h0 = Arrays.clone(bArr);
        this.f1216h1 = Arrays.clone(bArr2);
        this.sigma = Arrays.clone(bArr3);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f1215h0, this.f1216h1, this.sigma);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getH0() {
        return this.f1215h0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getH1() {
        return this.f1216h1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getSigma() {
        return this.sigma;
    }
}