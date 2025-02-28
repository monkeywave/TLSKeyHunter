package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class MLKEMPublicKeyParameters extends MLKEMKeyParameters {
    final byte[] rho;

    /* renamed from: t */
    final byte[] f1353t;

    public MLKEMPublicKeyParameters(MLKEMParameters mLKEMParameters, byte[] bArr) {
        super(false, mLKEMParameters);
        this.f1353t = Arrays.copyOfRange(bArr, 0, bArr.length - 32);
        this.rho = Arrays.copyOfRange(bArr, bArr.length - 32, bArr.length);
    }

    public MLKEMPublicKeyParameters(MLKEMParameters mLKEMParameters, byte[] bArr, byte[] bArr2) {
        super(false, mLKEMParameters);
        this.f1353t = Arrays.clone(bArr);
        this.rho = Arrays.clone(bArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getEncoded(byte[] bArr, byte[] bArr2) {
        return Arrays.concatenate(bArr, bArr2);
    }

    public byte[] getEncoded() {
        return getEncoded(this.f1353t, this.rho);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getT() {
        return Arrays.clone(this.f1353t);
    }
}