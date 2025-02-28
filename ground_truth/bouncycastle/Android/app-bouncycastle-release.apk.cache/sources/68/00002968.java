package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.math.raw.Interleave;

/* loaded from: classes2.dex */
final class GF13 extends AbstractC1392GF {
    private int gf_mul_ext_par(short s, short s2, short s3, short s4) {
        int i = (s2 & 1) * s;
        int i2 = (s4 & 1) * s3;
        for (int i3 = 1; i3 < 13; i3++) {
            int i4 = 1 << i3;
            i ^= (s2 & i4) * s;
            i2 ^= (i4 & s4) * s3;
        }
        return i ^ i2;
    }

    private short gf_sq2(short s) {
        return gf_reduce(Interleave.expand16to32(gf_reduce(Interleave.expand16to32(s))));
    }

    private short gf_sq2mul(short s, short s2) {
        long j = s;
        long j2 = s2;
        long j3 = (j2 << 18) * (64 & j);
        long j4 = j ^ (j << 21);
        long j5 = ((j2 << 15) * (j4 & 8589934624L)) ^ (((((j3 ^ ((268435457 & j4) * j2)) ^ ((j2 << 3) * (536870914 & j4))) ^ ((j2 << 6) * (1073741828 & j4))) ^ ((j2 << 9) * (2147483656L & j4))) ^ ((j2 << 12) * (4294967312L & j4)));
        long j6 = 2305834213120671744L & j5;
        long j7 = j5 ^ ((j6 >>> 26) ^ (((j6 >>> 18) ^ (j6 >>> 20)) ^ (j6 >>> 24)));
        long j8 = 8796025913344L & j7;
        return gf_reduce(((int) (j7 ^ ((j8 >>> 26) ^ (((j8 >>> 18) ^ (j8 >>> 20)) ^ (j8 >>> 24))))) & 67108863);
    }

    private short gf_sqmul(short s, short s2) {
        long j = s;
        long j2 = s2;
        long j3 = (j2 << 6) * (64 & j);
        long j4 = j ^ (j << 7);
        long j5 = ((j2 << 5) * (j4 & 524320)) ^ (((((j3 ^ ((16385 & j4) * j2)) ^ ((j2 << 1) * (32770 & j4))) ^ ((j2 << 2) * (65540 & j4))) ^ ((j2 << 3) * (131080 & j4))) ^ ((j2 << 4) * (262160 & j4)));
        long j6 = 137371844608L & j5;
        return gf_reduce(((int) (j5 ^ ((j6 >>> 26) ^ (((j6 >>> 18) ^ (j6 >>> 20)) ^ (j6 >>> 24))))) & 67108863);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_frac(short s, short s2) {
        short gf_sqmul = gf_sqmul(s, s);
        short gf_sq2mul = gf_sq2mul(gf_sqmul, gf_sqmul);
        return gf_sqmul(gf_sq2mul(gf_sq2(gf_sq2mul(gf_sq2(gf_sq2mul), gf_sq2mul)), gf_sq2mul), s2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_inv(short s) {
        return gf_frac(s, (short) 1);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_mul(short s, short s2) {
        int i = (s2 & 1) * s;
        for (int i2 = 1; i2 < 13; i2++) {
            i ^= ((1 << i2) & s2) * s;
        }
        return gf_reduce(i);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public int gf_mul_ext(short s, short s2) {
        int i = (s2 & 1) * s;
        for (int i2 = 1; i2 < 13; i2++) {
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
            for (int i8 : iArr) {
                int i9 = (i6 - i) + i8;
                iArr2[i9] = iArr2[i9] ^ i7;
            }
        }
        for (int i10 = 0; i10 < i; i10++) {
            sArr[i10] = gf_reduce(iArr2[i10]);
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.pqc.crypto.cmce.AbstractC1392GF
    public short gf_reduce(int i) {
        int i2 = i & 8191;
        int i3 = i >>> 13;
        int i4 = ((i3 << 4) ^ (i3 << 3)) ^ (i3 << 1);
        int i5 = i4 >>> 13;
        return (short) ((((i3 ^ i2) ^ i5) ^ (i4 & 8191)) ^ (((i5 << 4) ^ (i5 << 3)) ^ (i5 << 1)));
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
            for (int i6 : iArr) {
                int i7 = (i4 - i) + i6;
                iArr2[i7] = iArr2[i7] ^ i5;
            }
        }
        for (int i8 = 0; i8 < i; i8++) {
            sArr[i8] = gf_reduce(iArr2[i8]);
        }
    }
}