package org.bouncycastle.pqc.crypto.saber;

import kotlin.UByte;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Poly {
    private static final int KARATSUBA_N = 64;
    private static int SCHB_N = 16;
    private final int N_RES;
    private final int N_SB;
    private final int N_SB_RES;
    private final int SABER_L;
    private final int SABER_N;
    private final SABEREngine engine;
    private final Utils utils;

    public Poly(SABEREngine sABEREngine) {
        this.engine = sABEREngine;
        this.SABER_L = sABEREngine.getSABER_L();
        int saber_n = sABEREngine.getSABER_N();
        this.SABER_N = saber_n;
        this.N_RES = saber_n << 1;
        int i = saber_n >> 2;
        this.N_SB = i;
        this.N_SB_RES = (i * 2) - 1;
        this.utils = sABEREngine.getUtils();
    }

    private short OVERFLOWING_MUL(int i, int i2) {
        return (short) (i * i2);
    }

    private void cbd(short[] sArr, byte[] bArr, int i) {
        int[] iArr = new int[4];
        if (this.engine.getSABER_MU() == 6) {
            for (int i2 = 0; i2 < this.SABER_N / 4; i2++) {
                int load_littleendian = (int) load_littleendian(bArr, i + (i2 * 3), 3);
                int i3 = 0;
                for (int i4 = 0; i4 < 3; i4++) {
                    i3 += (load_littleendian >> i4) & 2396745;
                }
                iArr[0] = i3 & 7;
                iArr[1] = (i3 >>> 6) & 7;
                iArr[2] = (i3 >>> 12) & 7;
                iArr[3] = (i3 >>> 18) & 7;
                int i5 = i2 * 4;
                sArr[i5] = (short) (iArr[0] - ((i3 >>> 3) & 7));
                sArr[i5 + 1] = (short) (iArr[1] - ((i3 >>> 9) & 7));
                sArr[i5 + 2] = (short) (iArr[2] - ((i3 >>> 15) & 7));
                sArr[i5 + 3] = (short) (iArr[3] - (i3 >>> 21));
            }
            return;
        }
        char c = 15;
        if (this.engine.getSABER_MU() == 8) {
            for (int i6 = 0; i6 < this.SABER_N / 4; i6++) {
                int i7 = i6 * 4;
                int load_littleendian2 = (int) load_littleendian(bArr, i + i7, 4);
                int i8 = 0;
                for (int i9 = 0; i9 < 4; i9++) {
                    i8 += (load_littleendian2 >>> i9) & 286331153;
                }
                iArr[0] = i8 & 15;
                iArr[1] = (i8 >>> 8) & 15;
                iArr[2] = (i8 >>> 16) & 15;
                iArr[3] = (i8 >>> 24) & 15;
                sArr[i7] = (short) (iArr[0] - ((i8 >>> 4) & 15));
                sArr[i7 + 1] = (short) (iArr[1] - ((i8 >>> 12) & 15));
                sArr[i7 + 2] = (short) (iArr[2] - ((i8 >>> 20) & 15));
                sArr[i7 + 3] = (short) (iArr[3] - (i8 >>> 28));
            }
        } else if (this.engine.getSABER_MU() == 10) {
            int i10 = 0;
            while (i10 < this.SABER_N / 4) {
                long load_littleendian3 = load_littleendian(bArr, i + (i10 * 5), 5);
                long j = 0;
                for (int i11 = 0; i11 < 5; i11++) {
                    j += (load_littleendian3 >>> i11) & 35468117025L;
                }
                iArr[0] = (int) (j & 31);
                iArr[1] = (int) ((j >>> 10) & 31);
                iArr[2] = (int) ((j >>> 20) & 31);
                iArr[3] = (int) ((j >>> 30) & 31);
                int i12 = i10 * 4;
                sArr[i12] = (short) (iArr[0] - ((int) ((j >>> 5) & 31)));
                sArr[i12 + 1] = (short) (iArr[1] - ((int) ((j >>> c) & 31)));
                sArr[i12 + 2] = (short) (iArr[2] - ((int) ((j >>> 25) & 31)));
                sArr[i12 + 3] = (short) (iArr[3] - ((int) (j >>> 35)));
                i10++;
                c = 15;
            }
        }
    }

    private void karatsuba_simple(int[] iArr, int[] iArr2, int[] iArr3) {
        int i = 31;
        int[] iArr4 = new int[31];
        int[] iArr5 = new int[31];
        int[] iArr6 = new int[31];
        int[] iArr7 = new int[63];
        int i2 = 0;
        while (true) {
            if (i2 >= 16) {
                break;
            }
            int i3 = iArr[i2];
            int i4 = iArr[i2 + 16];
            int i5 = iArr[i2 + 32];
            int i6 = iArr[i2 + 48];
            int i7 = 0;
            for (int i8 = 16; i7 < i8; i8 = 16) {
                int i9 = iArr2[i7];
                int i10 = iArr2[i7 + 16];
                int i11 = i2 + i7;
                iArr3[i11] = iArr3[i11] + OVERFLOWING_MUL(i3, i9);
                int i12 = i11 + 32;
                iArr3[i12] = iArr3[i12] + OVERFLOWING_MUL(i4, i10);
                int i13 = i9 + i10;
                int i14 = i3;
                int[] iArr8 = iArr7;
                iArr4[i11] = (int) (iArr4[i11] + (i13 * (i3 + i4)));
                int i15 = iArr2[i7 + 32];
                int i16 = iArr2[i7 + 48];
                int i17 = i11 + 64;
                iArr3[i17] = iArr3[i17] + OVERFLOWING_MUL(i15, i5);
                int i18 = i11 + 96;
                iArr3[i18] = iArr3[i18] + OVERFLOWING_MUL(i16, i6);
                iArr6[i11] = iArr6[i11] + OVERFLOWING_MUL(i5 + i6, i15 + i16);
                int i19 = i9 + i15;
                int i20 = i14 + i5;
                iArr8[i11] = iArr8[i11] + OVERFLOWING_MUL(i19, i20);
                int i21 = i10 + i16;
                int i22 = i4 + i6;
                iArr8[i12] = iArr8[i12] + OVERFLOWING_MUL(i21, i22);
                iArr5[i11] = iArr5[i11] + OVERFLOWING_MUL(i19 + i21, i20 + i22);
                i7++;
                i3 = i14;
                i2 = i2;
                iArr7 = iArr8;
            }
            i2++;
            i = 31;
        }
        int[] iArr9 = iArr7;
        int i23 = i;
        int i24 = 0;
        while (i24 < i23) {
            int i25 = i24 + 32;
            iArr5[i24] = (iArr5[i24] - iArr9[i24]) - iArr9[i25];
            iArr4[i24] = (iArr4[i24] - iArr3[i24]) - iArr3[i25];
            iArr6[i24] = (iArr6[i24] - iArr3[i24 + 64]) - iArr3[i24 + 96];
            i24++;
            i23 = 31;
        }
        for (int i26 = 0; i26 < i23; i26++) {
            int i27 = i26 + 16;
            iArr9[i27] = iArr9[i27] + iArr5[i26];
            iArr3[i27] = iArr3[i27] + iArr4[i26];
            int i28 = i26 + 80;
            iArr3[i28] = iArr3[i28] + iArr6[i26];
        }
        for (int i29 = 0; i29 < 63; i29++) {
            iArr9[i29] = (iArr9[i29] - iArr3[i29]) - iArr3[i29 + 64];
        }
        for (int i30 = 0; i30 < 63; i30++) {
            int i31 = i30 + 32;
            iArr3[i31] = iArr3[i31] + iArr9[i30];
        }
    }

    private long load_littleendian(byte[] bArr, int i, int i2) {
        long j = bArr[i] & UByte.MAX_VALUE;
        for (int i3 = 1; i3 < i2; i3++) {
            j |= (bArr[i + i3] & UByte.MAX_VALUE) << (i3 * 8);
        }
        return j;
    }

    private void poly_mul_acc(short[] sArr, short[] sArr2, short[] sArr3) {
        short[] sArr4 = new short[this.SABER_N * 2];
        toom_cook_4way(sArr, sArr2, sArr4);
        int i = this.SABER_N;
        while (true) {
            int i2 = this.SABER_N;
            if (i >= i2 * 2) {
                return;
            }
            int i3 = i - i2;
            sArr3[i3] = (short) (sArr3[i3] + (sArr4[i - i2] - sArr4[i]));
            i++;
        }
    }

    private void toom_cook_4way(short[] sArr, short[] sArr2, short[] sArr3) {
        int i = this.N_SB;
        int[] iArr = new int[i];
        int[] iArr2 = new int[i];
        int[] iArr3 = new int[i];
        int[] iArr4 = new int[i];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        int[] iArr7 = new int[i];
        int[] iArr8 = new int[i];
        int[] iArr9 = new int[i];
        int[] iArr10 = new int[i];
        int[] iArr11 = new int[i];
        int[] iArr12 = new int[i];
        int[] iArr13 = new int[i];
        int[] iArr14 = new int[i];
        int i2 = this.N_SB_RES;
        int[] iArr15 = new int[i2];
        int[] iArr16 = new int[i2];
        int[] iArr17 = new int[i2];
        int[] iArr18 = new int[i2];
        int[] iArr19 = new int[i2];
        int[] iArr20 = new int[i2];
        int[] iArr21 = new int[i2];
        int i3 = 0;
        while (true) {
            int i4 = this.N_SB;
            if (i3 >= i4) {
                break;
            }
            short s = sArr[i3];
            short s2 = sArr[i3 + i4];
            short s3 = sArr[i3 + (i4 * 2)];
            short s4 = sArr[(i4 * 3) + i3];
            int[] iArr22 = iArr14;
            short s5 = (short) (s + s3);
            int[] iArr23 = iArr9;
            short s6 = (short) (s2 + s4);
            iArr3[i3] = (short) (s5 + s6);
            iArr4[i3] = (short) (s5 - s6);
            short s7 = (short) (((s << 2) + s3) << 1);
            short s8 = (short) ((s2 << 2) + s4);
            iArr5[i3] = (short) (s7 + s8);
            iArr6[i3] = (short) (s7 - s8);
            iArr2[i3] = (short) ((s4 << 3) + (s3 << 2) + (s2 << 1) + s);
            iArr7[i3] = s;
            iArr[i3] = s4;
            i3++;
            iArr14 = iArr22;
            iArr9 = iArr23;
            iArr13 = iArr13;
        }
        int[] iArr24 = iArr14;
        int[] iArr25 = iArr9;
        int[] iArr26 = iArr13;
        int i5 = 0;
        while (true) {
            int i6 = this.N_SB;
            if (i5 >= i6) {
                break;
            }
            short s9 = sArr2[i5];
            short s10 = sArr2[i5 + i6];
            short s11 = sArr2[(i6 * 2) + i5];
            short s12 = sArr2[(i6 * 3) + i5];
            int i7 = s9 + s11;
            int i8 = s10 + s12;
            iArr10[i5] = i7 + i8;
            iArr11[i5] = i7 - i8;
            int i9 = ((s9 << 2) + s11) << 1;
            int i10 = (s10 << 2) + s12;
            iArr12[i5] = i9 + i10;
            iArr26[i5] = i9 - i10;
            iArr25[i5] = (s12 << 3) + (s11 << 2) + (s10 << 1) + s9;
            iArr24[i5] = s9;
            iArr8[i5] = s12;
            i5++;
        }
        karatsuba_simple(iArr, iArr8, iArr15);
        karatsuba_simple(iArr2, iArr25, iArr16);
        karatsuba_simple(iArr3, iArr10, iArr17);
        karatsuba_simple(iArr4, iArr11, iArr18);
        karatsuba_simple(iArr5, iArr12, iArr19);
        karatsuba_simple(iArr6, iArr26, iArr20);
        karatsuba_simple(iArr7, iArr24, iArr21);
        for (int i11 = 0; i11 < this.N_SB_RES; i11++) {
            int i12 = iArr15[i11];
            int i13 = iArr16[i11];
            int i14 = iArr17[i11];
            int i15 = iArr18[i11];
            int i16 = iArr19[i11];
            int i17 = iArr20[i11];
            int i18 = iArr21[i11];
            int i19 = i17 - i16;
            int i20 = ((i15 & 65535) - (i14 & 65535)) >>> 1;
            int i21 = i14 + i20;
            int i22 = ((i13 + i16) - (i21 << 6)) - i21;
            int i23 = (i21 - i18) - i12;
            int i24 = i22 + (i23 * 45);
            int i25 = (((((((i16 - i12) - (i18 << 6)) << 1) + i19) & 65535) - (i23 << 3)) * 43691) >> 3;
            int i26 = i19 + i24;
            int i27 = (((i24 & 65535) + ((i20 & 65535) << 4)) * 36409) >> 1;
            int i28 = ((((i27 & 65535) * 30) - (i26 & 65535)) * 61167) >> 2;
            int i29 = i23 - i25;
            int i30 = i27 - i28;
            sArr3[i11] = (short) (sArr3[i11] + (i18 & 65535));
            int i31 = i11 + 64;
            sArr3[i31] = (short) (sArr3[i31] + (i28 & 65535));
            int i32 = i11 + 128;
            sArr3[i32] = (short) (sArr3[i32] + (i25 & 65535));
            int i33 = i11 + 192;
            sArr3[i33] = (short) (sArr3[i33] + ((-(i20 + i27)) & 65535));
            int i34 = i11 + 256;
            sArr3[i34] = (short) (sArr3[i34] + (i29 & 65535));
            int i35 = i11 + 320;
            sArr3[i35] = (short) (sArr3[i35] + (i30 & 65535));
            int i36 = i11 + MLKEMEngine.KyberPolyBytes;
            sArr3[i36] = (short) (sArr3[i36] + (i12 & 65535));
        }
    }

    public void GenMatrix(short[][][] sArr, byte[] bArr) {
        int saber_polyvecbytes = this.SABER_L * this.engine.getSABER_POLYVECBYTES();
        byte[] bArr2 = new byte[saber_polyvecbytes];
        this.engine.symmetric.prf(bArr2, bArr, this.engine.getSABER_SEEDBYTES(), saber_polyvecbytes);
        for (int i = 0; i < this.SABER_L; i++) {
            this.utils.BS2POLVECq(bArr2, this.engine.getSABER_POLYVECBYTES() * i, sArr[i]);
        }
    }

    public void GenSecret(short[][] sArr, byte[] bArr) {
        int saber_polycoinbytes = this.SABER_L * this.engine.getSABER_POLYCOINBYTES();
        byte[] bArr2 = new byte[saber_polycoinbytes];
        this.engine.symmetric.prf(bArr2, bArr, this.engine.getSABER_NOISE_SEEDBYTES(), saber_polycoinbytes);
        for (int i = 0; i < this.SABER_L; i++) {
            if (this.engine.usingEffectiveMasking) {
                for (int i2 = 0; i2 < this.SABER_N / 4; i2++) {
                    int i3 = i2 * 4;
                    sArr[i][i3] = (short) (((bArr2[(this.engine.getSABER_POLYCOINBYTES() * i) + i2] & 3) ^ 2) - 2);
                    sArr[i][i3 + 1] = (short) ((((bArr2[(this.engine.getSABER_POLYCOINBYTES() * i) + i2] >>> 2) & 3) ^ 2) - 2);
                    sArr[i][i3 + 2] = (short) ((((bArr2[(this.engine.getSABER_POLYCOINBYTES() * i) + i2] >>> 4) & 3) ^ 2) - 2);
                    sArr[i][i3 + 3] = (short) ((((bArr2[(this.engine.getSABER_POLYCOINBYTES() * i) + i2] >>> 6) & 3) ^ 2) - 2);
                }
            } else {
                cbd(sArr[i], bArr2, this.engine.getSABER_POLYCOINBYTES() * i);
            }
        }
    }

    public void InnerProd(short[][] sArr, short[][] sArr2, short[] sArr3) {
        for (int i = 0; i < this.SABER_L; i++) {
            poly_mul_acc(sArr[i], sArr2[i], sArr3);
        }
    }

    public void MatrixVectorMul(short[][][] sArr, short[][] sArr2, short[][] sArr3, int i) {
        for (int i2 = 0; i2 < this.SABER_L; i2++) {
            for (int i3 = 0; i3 < this.SABER_L; i3++) {
                if (i == 1) {
                    poly_mul_acc(sArr[i3][i2], sArr2[i3], sArr3[i2]);
                } else {
                    poly_mul_acc(sArr[i2][i3], sArr2[i3], sArr3[i2]);
                }
            }
        }
    }
}