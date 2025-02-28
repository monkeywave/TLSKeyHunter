package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class NTRULPRimePrivateKeyParameters extends NTRULPRimeKeyParameters {
    private final byte[] enca;
    private final byte[] hash;

    /* renamed from: pk */
    private final byte[] f1363pk;
    private final byte[] rho;

    public NTRULPRimePrivateKeyParameters(NTRULPRimeParameters nTRULPRimeParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        super(true, nTRULPRimeParameters);
        this.enca = Arrays.clone(bArr);
        this.f1363pk = Arrays.clone(bArr2);
        this.rho = Arrays.clone(bArr3);
        this.hash = Arrays.clone(bArr4);
    }

    public byte[] getEnca() {
        return Arrays.clone(this.enca);
    }

    public byte[] getEncoded() {
        byte[] bArr = new byte[getParameters().getPrivateKeyBytes()];
        byte[] bArr2 = this.enca;
        System.arraycopy(bArr2, 0, bArr, 0, bArr2.length);
        byte[] bArr3 = this.f1363pk;
        System.arraycopy(bArr3, 0, bArr, this.enca.length, bArr3.length);
        byte[] bArr4 = this.rho;
        System.arraycopy(bArr4, 0, bArr, this.enca.length + this.f1363pk.length, bArr4.length);
        byte[] bArr5 = this.hash;
        System.arraycopy(bArr5, 0, bArr, this.enca.length + this.f1363pk.length + this.rho.length, bArr5.length);
        return bArr;
    }

    public byte[] getHash() {
        return Arrays.clone(this.hash);
    }

    public byte[] getPk() {
        return Arrays.clone(this.f1363pk);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }
}