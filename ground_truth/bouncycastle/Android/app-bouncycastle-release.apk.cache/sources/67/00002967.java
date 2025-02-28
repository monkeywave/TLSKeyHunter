package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.math.raw.Interleave;

/* loaded from: classes2.dex */
final class GF12 extends AbstractC1392GF {
    private int gf_mul_ext_par(short s, short s2, short s3, short s4) {
        int i = (s2 & 1) * s;
        int i2 = (s4 & 1) * s3;
        for (int i3 = 1; i3 < 12; i3++) {
            int i4 = 1 << i3;
            i ^= (s2 & i4) * s;
            i2 ^= (i4 & s4) * s3;
        }
        return i ^ i2;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_frac(short s, short s2) {
        return gf_mul(gf_inv(s), s2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_inv(short s) {
        short gf_mul = gf_mul(gf_sq(s), s);
        short gf_mul2 = gf_mul(gf_sq(gf_sq(gf_mul)), gf_mul);
        return gf_sq(gf_mul(gf_sq(gf_mul(gf_sq(gf_sq(gf_mul(gf_sq(gf_sq(gf_sq(gf_sq(gf_mul2)))), gf_mul2))), gf_mul)), s));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_mul(short s, short s2) {
        int i = (s2 & 1) * s;
        for (int i2 = 1; i2 < 12; i2++) {
            i ^= ((1 << i2) & s2) * s;
        }
        return gf_reduce(i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public int gf_mul_ext(short s, short s2) {
        int i = (s2 & 1) * s;
        for (int i2 = 1; i2 < 12; i2++) {
            i ^= ((1 << i2) & s2) * s;
        }
        return i;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public void gf_mul_poly(int i, int[] iArr, short[] sArr, short[] sArr2, short[] sArr3, int[] iArr2) {
        iArr2[0] = gf_mul_ext(sArr2[0], sArr3[0]);
        for (int i2 = 1; i2 < i; i2++) {
            int i3 = i2 + i2;
            iArr2[i3 - 1] = 0;
            short s = sArr2[i2];
            short s2 = sArr3[i2];
            for (int i4 = 0; i4 < i2; i4++) {
                int i5 = i2 + i4;
                iArr2[i5] = iArr2[i5] ^ gf_mul_ext_par(s, sArr3[i4], sArr2[i4], s2);
            }
            iArr2[i3] = gf_mul_ext(s, s2);
        }
        for (int i6 = (i - 1) * 2; i6 >= i; i6--) {
            int i7 = iArr2[i6];
            for (int i8 = 0; i8 < iArr.length - 1; i8++) {
                int i9 = (i6 - i) + iArr[i8];
                iArr2[i9] = iArr2[i9] ^ i7;
            }
            int i10 = i6 - i;
            iArr2[i10] = (i7 << 1) ^ iArr2[i10];
        }
        for (int i11 = 0; i11 < i; i11++) {
            sArr[i11] = gf_reduce(iArr2[i11]);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_reduce(int i) {
        return (short) ((i >>> 21) ^ ((((i & 4095) ^ (i >>> 12)) ^ ((2093056 & i) >>> 9)) ^ ((14680064 & i) >>> 18)));
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_sq(short s) {
        return gf_reduce(Interleave.expand16to32(s));
    }

    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    protected int gf_sq_ext(short s) {
        return Interleave.expand16to32(s);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public void gf_sqr_poly(int i, int[] iArr, short[] sArr, short[] sArr2, int[] iArr2) {
        iArr2[0] = gf_sq_ext(sArr2[0]);
        for (int i2 = 1; i2 < i; i2++) {
            int i3 = i2 + i2;
            iArr2[i3 - 1] = 0;
            iArr2[i3] = gf_sq_ext(sArr2[i2]);
        }
        for (int i4 = (i - 1) * 2; i4 >= i; i4--) {
            int i5 = iArr2[i4];
            for (int i6 = 0; i6 < iArr.length - 1; i6++) {
                int i7 = (i4 - i) + iArr[i6];
                iArr2[i7] = iArr2[i7] ^ i5;
            }
            int i8 = i4 - i;
            iArr2[i8] = (i5 << 1) ^ iArr2[i8];
        }
        for (int i9 = 0; i9 < i; i9++) {
            sArr[i9] = gf_reduce(iArr2[i9]);
        }
    }
}