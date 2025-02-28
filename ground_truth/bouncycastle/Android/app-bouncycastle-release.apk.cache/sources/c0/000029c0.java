package org.bouncycastle.pqc.crypto.hqc;

/* loaded from: classes2.dex */
class FastFourierTransform {
    FastFourierTransform() {
    }

    static void computeFFTBetas(int[] iArr, int i) {
        int i2 = 0;
        while (true) {
            int i3 = i - 1;
            if (i2 >= i3) {
                return;
            }
            iArr[i2] = 1 << (i3 - i2);
            i2++;
        }
    }

    static void computeFFTRec(int[] iArr, int[] iArr2, int i, int i2, int i3, int[] iArr3, int i4, int i5) {
        int i6 = 1;
        int i7 = 1 << (i4 - 2);
        int i8 = i5 - 2;
        int i9 = 1 << i8;
        int[] iArr4 = new int[i7];
        int[] iArr5 = new int[i7];
        int[] iArr6 = new int[i8];
        int[] iArr7 = new int[i8];
        int[] iArr8 = new int[i9];
        int[] iArr9 = new int[i9];
        int[] iArr10 = new int[i9];
        int[] iArr11 = new int[(i5 - i4) + 1];
        if (i3 == 1) {
            for (int i10 = 0; i10 < i2; i10++) {
                iArr11[i10] = GFCalculator.mult(iArr3[i10], iArr2[1]);
            }
            iArr[0] = iArr2[0];
            for (int i11 = 0; i11 < i2; i11++) {
                for (int i12 = 0; i12 < i6; i12++) {
                    iArr[i6 + i12] = iArr[i12] ^ iArr11[i11];
                }
                i6 <<= 1;
            }
            return;
        }
        int i13 = i2 - 1;
        if (iArr3[i13] != 1) {
            int i14 = 1;
            for (int i15 = 1 << i3; i14 < i15; i15 = i15) {
                i6 = GFCalculator.mult(i6, iArr3[i13]);
                iArr2[i14] = GFCalculator.mult(i6, iArr2[i14]);
                i14++;
            }
        }
        computeRadix(iArr4, iArr5, iArr2, i3, i4);
        for (int i16 = 0; i16 < i13; i16++) {
            int mult = GFCalculator.mult(iArr3[i16], GFCalculator.inverse(iArr3[i13]));
            iArr6[i16] = mult;
            iArr7[i16] = GFCalculator.mult(mult, mult) ^ iArr6[i16];
        }
        computeSubsetSum(iArr8, iArr6, i13);
        int i17 = i3 - 1;
        computeFFTRec(iArr9, iArr4, (i + 1) / 2, i13, i17, iArr7, i4, i5);
        int i18 = 1 << (i13 & 15);
        if (i <= 3) {
            iArr[0] = iArr9[0];
            iArr[i18] = iArr9[0] ^ iArr5[0];
            for (int i19 = 1; i19 < i18; i19++) {
                int mult2 = iArr9[i19] ^ GFCalculator.mult(iArr8[i19], iArr5[0]);
                iArr[i19] = mult2;
                iArr[i18 + i19] = mult2 ^ iArr5[0];
            }
            return;
        }
        computeFFTRec(iArr10, iArr5, i / 2, i13, i17, iArr7, i4, i5);
        System.arraycopy(iArr10, 0, iArr, i18, i18);
        iArr[0] = iArr9[0];
        iArr[i18] = iArr[i18] ^ iArr9[0];
        for (int i20 = 1; i20 < i18; i20++) {
            int mult3 = iArr9[i20] ^ GFCalculator.mult(iArr8[i20], iArr10[i20]);
            iArr[i20] = mult3;
            int i21 = i18 + i20;
            iArr[i21] = mult3 ^ iArr[i21];
        }
    }

    static void computeRadix(int[] iArr, int[] iArr2, int[] iArr3, int i, int i2) {
        if (i == 1) {
            iArr[0] = iArr3[0];
            iArr2[0] = iArr3[1];
        } else if (i == 2) {
            iArr[0] = iArr3[0];
            int i3 = iArr3[2];
            int i4 = iArr3[3];
            int i5 = i3 ^ i4;
            iArr[1] = i5;
            iArr2[0] = i5 ^ iArr3[1];
            iArr2[1] = i4;
        } else if (i == 3) {
            iArr[0] = iArr3[0];
            int i6 = iArr3[4];
            int i7 = iArr3[6];
            iArr[2] = i6 ^ i7;
            int i8 = iArr3[7];
            iArr[3] = i7 ^ i8;
            int i9 = iArr3[3];
            int i10 = iArr3[5];
            int i11 = (i9 ^ i10) ^ i8;
            iArr2[1] = i11;
            iArr2[2] = i10 ^ i7;
            iArr2[3] = i8;
            int i12 = (iArr3[2] ^ iArr[2]) ^ i11;
            iArr[1] = i12;
            iArr2[0] = i12 ^ iArr3[1];
        } else if (i != 4) {
            computeRadixBig(iArr, iArr2, iArr3, i, i2);
        } else {
            int i13 = iArr3[8];
            int i14 = iArr3[12];
            iArr[4] = i13 ^ i14;
            int i15 = iArr3[14];
            iArr[6] = i14 ^ i15;
            int i16 = iArr3[15];
            iArr[7] = i15 ^ i16;
            int i17 = iArr3[11];
            int i18 = iArr3[13];
            int i19 = i17 ^ i18;
            iArr2[5] = i19;
            iArr2[6] = i18 ^ i15;
            iArr2[7] = i16;
            int i20 = iArr3[10];
            int i21 = (i14 ^ i20) ^ i19;
            iArr[5] = i21;
            int i22 = iArr3[9];
            iArr2[4] = i21 ^ (i22 ^ i18);
            iArr[0] = iArr3[0];
            int i23 = (iArr3[7] ^ i17) ^ i16;
            iArr2[3] = i23;
            int i24 = (i15 ^ (iArr3[6] ^ i20)) ^ i23;
            iArr[3] = i24;
            int i25 = iArr2[3];
            iArr[2] = ((iArr3[4] ^ iArr[4]) ^ i24) ^ i25;
            int i26 = iArr3[3];
            int i27 = (((iArr3[5] ^ i26) ^ i22) ^ i18) ^ i25;
            iArr2[1] = i27;
            iArr2[2] = i24 ^ (i26 ^ i27);
            int i28 = (iArr3[2] ^ iArr[2]) ^ i27;
            iArr[1] = i28;
            iArr2[0] = i28 ^ iArr3[1];
        }
    }

    static void computeRadixBig(int[] iArr, int[] iArr2, int[] iArr3, int i, int i2) {
        int i3 = 1 << (i - 2);
        int i4 = 1 << (i2 - 2);
        int i5 = i4 * 2;
        int[] iArr4 = new int[i5];
        int[] iArr5 = new int[i5];
        int[] iArr6 = new int[i4];
        int[] iArr7 = new int[i4];
        int[] iArr8 = new int[i4];
        int[] iArr9 = new int[i4];
        int i6 = i3 * 3;
        int i7 = i3 * 2;
        Utils.copyBytes(iArr3, i6, iArr4, 0, i7);
        Utils.copyBytes(iArr3, i6, iArr4, i3, i7);
        Utils.copyBytes(iArr3, 0, iArr5, 0, i3 * 4);
        for (int i8 = 0; i8 < i3; i8++) {
            int i9 = iArr4[i8] ^ iArr3[i7 + i8];
            iArr4[i8] = i9;
            int i10 = i3 + i8;
            iArr5[i10] = iArr5[i10] ^ i9;
        }
        int i11 = i - 1;
        computeRadix(iArr6, iArr7, iArr4, i11, i2);
        computeRadix(iArr8, iArr9, iArr5, i11, i2);
        Utils.copyBytes(iArr8, 0, iArr, 0, i7);
        Utils.copyBytes(iArr6, 0, iArr, i3, i7);
        Utils.copyBytes(iArr9, 0, iArr2, 0, i7);
        Utils.copyBytes(iArr7, 0, iArr2, i3, i7);
    }

    static void computeSubsetSum(int[] iArr, int[] iArr2, int i) {
        iArr[0] = 0;
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = 0;
            while (true) {
                int i4 = 1 << i2;
                if (i3 < i4) {
                    iArr[i4 + i3] = iArr2[i2] ^ iArr[i3];
                    i3++;
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void fastFourierTransform(int[] iArr, int[] iArr2, int i, int i2) {
        int i3 = 1 << i2;
        int[] iArr3 = new int[i3];
        int[] iArr4 = new int[i3];
        int[] iArr5 = new int[7];
        int[] iArr6 = new int[128];
        int[] iArr7 = new int[128];
        int[] iArr8 = new int[7];
        int[] iArr9 = new int[128];
        computeFFTBetas(iArr8, 8);
        computeSubsetSum(iArr9, iArr8, 7);
        computeRadix(iArr3, iArr4, iArr2, i2, i2);
        for (int i4 = 0; i4 < 7; i4++) {
            int i5 = iArr8[i4];
            iArr5[i4] = GFCalculator.mult(i5, i5) ^ iArr8[i4];
        }
        int i6 = i2 - 1;
        computeFFTRec(iArr6, iArr3, (i + 1) / 2, 7, i6, iArr5, i2, 8);
        computeFFTRec(iArr7, iArr4, i / 2, 7, i6, iArr5, i2, 8);
        System.arraycopy(iArr7, 0, iArr, 128, 128);
        iArr[0] = iArr6[0];
        iArr[128] = iArr[128] ^ iArr6[0];
        for (int i7 = 1; i7 < 128; i7++) {
            int mult = iArr6[i7] ^ GFCalculator.mult(iArr9[i7], iArr7[i7]);
            iArr[i7] = mult;
            int i8 = 128 + i7;
            iArr[i8] = mult ^ iArr[i8];
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void fastFourierTransformGetError(byte[] bArr, int[] iArr, int i, int[] iArr2) {
        int[] iArr3 = new int[7];
        int[] iArr4 = new int[i];
        computeFFTBetas(iArr3, 8);
        computeSubsetSum(iArr4, iArr3, 7);
        byte unsigned16Bits = (byte) (bArr[0] ^ (Utils.toUnsigned16Bits((-iArr[0]) >> 15) ^ 1));
        bArr[0] = unsigned16Bits;
        bArr[0] = (byte) (unsigned16Bits ^ (Utils.toUnsigned16Bits((-iArr[i]) >> 15) ^ 1));
        for (int i2 = 1; i2 < i; i2++) {
            int i3 = 255 - iArr2[iArr4[i2]];
            bArr[i3] = (byte) (bArr[i3] ^ (Math.abs((-iArr[i2]) >> 15) ^ 1));
            int i4 = 255 - iArr2[iArr4[i2] ^ 1];
            bArr[i4] = (byte) (bArr[i4] ^ (Math.abs((-iArr[i + i2]) >> 15) ^ 1));
        }
    }
}