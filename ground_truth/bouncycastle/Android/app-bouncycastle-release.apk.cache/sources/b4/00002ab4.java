package org.bouncycastle.pqc.crypto.sphincsplus;

/* loaded from: classes2.dex */
class SIG {

    /* renamed from: r */
    private final byte[] f1423r;
    private final SIG_FORS[] sig_fors;
    private final SIG_XMSS[] sig_ht;

    public SIG(int i, int i2, int i3, int i4, int i5, int i6, byte[] bArr) {
        byte[] bArr2 = new byte[i];
        this.f1423r = bArr2;
        System.arraycopy(bArr, 0, bArr2, 0, i);
        this.sig_fors = new SIG_FORS[i2];
        int i7 = i;
        for (int i8 = 0; i8 != i2; i8++) {
            byte[] bArr3 = new byte[i];
            System.arraycopy(bArr, i7, bArr3, 0, i);
            i7 += i;
            byte[][] bArr4 = new byte[i3];
            for (int i9 = 0; i9 != i3; i9++) {
                byte[] bArr5 = new byte[i];
                bArr4[i9] = bArr5;
                System.arraycopy(bArr, i7, bArr5, 0, i);
                i7 += i;
            }
            this.sig_fors[i8] = new SIG_FORS(bArr3, bArr4);
        }
        this.sig_ht = new SIG_XMSS[i4];
        for (int i10 = 0; i10 != i4; i10++) {
            int i11 = i6 * i;
            byte[] bArr6 = new byte[i11];
            System.arraycopy(bArr, i7, bArr6, 0, i11);
            i7 += i11;
            byte[][] bArr7 = new byte[i5];
            for (int i12 = 0; i12 != i5; i12++) {
                byte[] bArr8 = new byte[i];
                bArr7[i12] = bArr8;
                System.arraycopy(bArr, i7, bArr8, 0, i);
                i7 += i;
            }
            this.sig_ht[i10] = new SIG_XMSS(bArr6, bArr7);
        }
        if (i7 != bArr.length) {
            throw new IllegalArgumentException("signature wrong length");
        }
    }

    public byte[] getR() {
        return this.f1423r;
    }

    public SIG_FORS[] getSIG_FORS() {
        return this.sig_fors;
    }

    public SIG_XMSS[] getSIG_HT() {
        return this.sig_ht;
    }
}