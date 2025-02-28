package org.bouncycastle.pqc.crypto.cmce;

import java.lang.reflect.Array;

/* loaded from: classes2.dex */
class BENES13 extends BENES {
    public BENES13(int i, int i2, int i3) {
        super(i, i2, i3);
    }

    static void layer_ex(long[] jArr, long[] jArr2, int i) {
        int i2 = 1 << i;
        int i3 = 0;
        for (int i4 = 0; i4 < 128; i4 += i2 * 2) {
            int i5 = i4;
            while (i5 < i4 + i2) {
                long j = jArr[i5];
                int i6 = i5 + i2;
                long j2 = (jArr[i6] ^ j) & jArr2[i3];
                jArr[i5] = j ^ j2;
                jArr[i6] = jArr[i6] ^ j2;
                i5++;
                i3++;
            }
        }
    }

    static void layer_in(long[] jArr, long[] jArr2, int i) {
        int i2 = 1 << i;
        int i3 = 0;
        for (int i4 = 0; i4 < 64; i4 += i2 * 2) {
            for (int i5 = i4; i5 < i4 + i2; i5++) {
                long j = jArr[i5];
                int i6 = i5 + i2;
                int i7 = i3 + 1;
                long j2 = (jArr[i6] ^ j) & jArr2[i3];
                jArr[i5] = j ^ j2;
                jArr[i6] = jArr[i6] ^ j2;
                int i8 = i5 + 64;
                long j3 = jArr[i8];
                int i9 = i8 + i2;
                i3 += 2;
                long j4 = jArr2[i7] & (jArr[i9] ^ j3);
                jArr[i8] = j3 ^ j4;
                jArr[i9] = jArr[i9] ^ j4;
            }
        }
    }

    void apply_benes(byte[] bArr, byte[] bArr2, int i) {
        int i2;
        int i3;
        int i4;
        long[] jArr = new long[128];
        long[] jArr2 = new long[128];
        long[] jArr3 = new long[64];
        long[] jArr4 = new long[64];
        if (i == 0) {
            i2 = (this.SYS_T * 2) + 40;
            i3 = 0;
        } else {
            i2 = (this.SYS_T * 2) + 12328;
            i3 = -1024;
        }
        for (int i5 = 0; i5 < 64; i5++) {
            int i6 = i5 * 16;
            jArr[i5] = Utils.load8(bArr, i6);
            jArr[i5 + 64] = Utils.load8(bArr, i6 + 8);
        }
        transpose_64x64(jArr2, jArr, 0);
        transpose_64x64(jArr2, jArr, 64);
        int i7 = 0;
        while (true) {
            if (i7 > 6) {
                break;
            }
            for (int i8 = 0; i8 < 64; i8++) {
                jArr3[i8] = Utils.load8(bArr2, i2);
                i2 += 8;
            }
            i2 += i3;
            transpose_64x64(jArr4, jArr3);
            layer_ex(jArr2, jArr4, i7);
            i7++;
        }
        transpose_64x64(jArr, jArr2, 0);
        transpose_64x64(jArr, jArr2, 64);
        for (int i9 = 0; i9 <= 5; i9++) {
            for (int i10 = 0; i10 < 64; i10++) {
                jArr3[i10] = Utils.load8(bArr2, i2);
                i2 += 8;
            }
            i2 += i3;
            layer_in(jArr, jArr3, i9);
        }
        for (int i11 = 4; i11 >= 0; i11--) {
            for (int i12 = 0; i12 < 64; i12++) {
                jArr3[i12] = Utils.load8(bArr2, i2);
                i2 += 8;
            }
            i2 += i3;
            layer_in(jArr, jArr3, i11);
        }
        transpose_64x64(jArr2, jArr, 0);
        transpose_64x64(jArr2, jArr, 64);
        for (i4 = 6; i4 >= 0; i4--) {
            for (int i13 = 0; i13 < 64; i13++) {
                jArr3[i13] = Utils.load8(bArr2, i2);
                i2 += 8;
            }
            i2 += i3;
            transpose_64x64(jArr4, jArr3);
            layer_ex(jArr2, jArr4, i4);
        }
        transpose_64x64(jArr, jArr2, 0);
        transpose_64x64(jArr, jArr2, 64);
        for (int i14 = 0; i14 < 64; i14++) {
            int i15 = i14 * 16;
            Utils.store8(bArr, i15, jArr[i14]);
            Utils.store8(bArr, i15 + 8, jArr[i14 + 64]);
        }
    }

    @Override // org.bouncycastle.pqc.crypto.cmce.BENES
    public void support_gen(short[] sArr, byte[] bArr) {
        byte[][] bArr2 = (byte[][]) Array.newInstance(Byte.TYPE, this.GFBITS, (1 << this.GFBITS) / 8);
        for (int i = 0; i < this.GFBITS; i++) {
            for (int i2 = 0; i2 < (1 << this.GFBITS) / 8; i2++) {
                bArr2[i][i2] = 0;
            }
        }
        for (int i3 = 0; i3 < (1 << this.GFBITS); i3++) {
            short bitrev = Utils.bitrev((short) i3, this.GFBITS);
            for (int i4 = 0; i4 < this.GFBITS; i4++) {
                byte[] bArr3 = bArr2[i4];
                int i5 = i3 / 8;
                bArr3[i5] = (byte) (bArr3[i5] | (((bitrev >> i4) & 1) << (i3 % 8)));
            }
        }
        for (int i6 = 0; i6 < this.GFBITS; i6++) {
            apply_benes(bArr2[i6], bArr, 0);
        }
        for (int i7 = 0; i7 < this.SYS_N; i7++) {
            sArr[i7] = 0;
            for (int i8 = this.GFBITS - 1; i8 >= 0; i8--) {
                short s = (short) (sArr[i7] << 1);
                sArr[i7] = s;
                sArr[i7] = (short) (s | ((bArr2[i8][i7 / 8] >> (i7 % 8)) & 1));
            }
        }
    }
}