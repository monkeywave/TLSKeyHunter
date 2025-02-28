package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class MLDSAPublicKeyParameters extends MLDSAKeyParameters {
    final byte[] rho;

    /* renamed from: t1 */
    final byte[] f1348t1;

    public MLDSAPublicKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr) {
        super(false, mLDSAParameters);
        this.rho = Arrays.copyOfRange(bArr, 0, 32);
        this.f1348t1 = Arrays.copyOfRange(bArr, 32, bArr.length);
    }

    public MLDSAPublicKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr, byte[] bArr2) {
        super(false, mLDSAParameters);
        this.rho = Arrays.clone(bArr);
        this.f1348t1 = Arrays.clone(bArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getEncoded(byte[] bArr, byte[] bArr2) {
        return Arrays.concatenate(bArr, bArr2);
    }

    public byte[] getEncoded() {
        return getEncoded(this.rho, this.f1348t1);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getT1() {
        return Arrays.clone(this.f1348t1);
    }
}