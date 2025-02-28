package org.bouncycastle.math.p016ec.rfc8032;

import org.bouncycastle.util.Integers;

/* renamed from: org.bouncycastle.math.ec.rfc8032.ScalarUtil */
/* loaded from: classes2.dex */
abstract class ScalarUtil {

    /* renamed from: M */
    private static final long f1138M = 4294967295L;

    ScalarUtil() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void addShifted_NP(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int[] iArr5 = iArr4;
        int i3 = 0;
        long j = 0;
        if (i2 == 0) {
            long j2 = 0;
            while (i3 <= i) {
                long j3 = iArr3[i3] & 4294967295L;
                long j4 = j2 + j3 + (iArr2[i3] & 4294967295L);
                int i4 = (int) j4;
                j2 = j4 >>> 32;
                iArr3[i3] = i4;
                long j5 = j + (iArr[i3] & 4294967295L) + j3 + (i4 & 4294967295L);
                iArr[i3] = (int) j5;
                j = j5 >>> 32;
                i3++;
            }
        } else if (i2 < 32) {
            int i5 = 0;
            long j6 = 0;
            long j7 = 0;
            int i6 = 0;
            int i7 = 0;
            while (i3 <= i) {
                int i8 = iArr3[i3];
                int i9 = -i2;
                long j8 = j6 + (iArr[i3] & 4294967295L) + (((i5 >>> i9) | (i8 << i2)) & 4294967295L);
                int i10 = iArr2[i3];
                long j9 = j7 + (i8 & 4294967295L) + (((i6 >>> i9) | (i10 << i2)) & 4294967295L);
                int i11 = (int) j9;
                j7 = j9 >>> 32;
                iArr3[i3] = i11;
                long j10 = j8 + (((i7 >>> i9) | (i11 << i2)) & 4294967295L);
                iArr[i3] = (int) j10;
                j6 = j10 >>> 32;
                i3++;
                i7 = i11;
                i6 = i10;
                i5 = i8;
            }
        } else {
            System.arraycopy(iArr3, 0, iArr5, 0, i);
            int i12 = i2 >>> 5;
            int i13 = i2 & 31;
            if (i13 == 0) {
                long j11 = 0;
                for (int i14 = i12; i14 <= i; i14++) {
                    int i15 = i14 - i12;
                    long j12 = j11 + (iArr3[i14] & 4294967295L) + (iArr2[i15] & 4294967295L);
                    iArr3[i14] = (int) j12;
                    j11 = j12 >>> 32;
                    long j13 = j + (iArr[i14] & 4294967295L) + (iArr5[i15] & 4294967295L) + (iArr3[i15] & 4294967295L);
                    iArr[i14] = (int) j13;
                    j = j13 >>> 32;
                }
                return;
            }
            int i16 = i12;
            long j14 = 0;
            long j15 = 0;
            int i17 = 0;
            int i18 = 0;
            while (i16 <= i) {
                int i19 = i16 - i12;
                int i20 = iArr5[i19];
                int i21 = -i13;
                int i22 = i12;
                long j16 = j14 + (iArr[i16] & 4294967295L) + (((i20 << i13) | (i3 >>> i21)) & 4294967295L);
                int i23 = iArr2[i19];
                long j17 = j15 + (iArr3[i16] & 4294967295L) + (((i23 << i13) | (i17 >>> i21)) & 4294967295L);
                iArr3[i16] = (int) j17;
                j15 = j17 >>> 32;
                int i24 = iArr3[i19];
                long j18 = j16 + (((i18 >>> i21) | (i24 << i13)) & 4294967295L);
                iArr[i16] = (int) j18;
                j14 = j18 >>> 32;
                i16++;
                iArr5 = iArr4;
                i18 = i24;
                i17 = i23;
                i3 = i20;
                i12 = i22;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void addShifted_UV(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int i3 = i;
        int i4 = i2 >>> 5;
        int i5 = i2 & 31;
        long j = 0;
        if (i5 == 0) {
            long j2 = 0;
            for (int i6 = i4; i6 <= i3; i6++) {
                int i7 = i6 - i4;
                long j3 = j + (iArr[i6] & 4294967295L) + (iArr3[i7] & 4294967295L);
                long j4 = j2 + (iArr2[i6] & 4294967295L) + (iArr4[i7] & 4294967295L);
                iArr[i6] = (int) j3;
                j = j3 >>> 32;
                iArr2[i6] = (int) j4;
                j2 = j4 >>> 32;
            }
            return;
        }
        int i8 = i4;
        int i9 = 0;
        int i10 = 0;
        long j5 = 0;
        while (i8 <= i3) {
            int i11 = i8 - i4;
            int i12 = iArr3[i11];
            int i13 = iArr4[i11];
            int i14 = -i5;
            long j6 = j + (iArr[i8] & 4294967295L) + (((i9 >>> i14) | (i12 << i5)) & 4294967295L);
            long j7 = j5 + (iArr2[i8] & 4294967295L) + (((i10 >>> i14) | (i13 << i5)) & 4294967295L);
            iArr[i8] = (int) j6;
            j = j6 >>> 32;
            iArr2[i8] = (int) j7;
            j5 = j7 >>> 32;
            i8++;
            i10 = i13;
            i9 = i12;
            i4 = i4;
            i3 = i;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getBitLength(int i, int[] iArr) {
        int i2 = iArr[i] >> 31;
        while (i > 0 && iArr[i] == i2) {
            i--;
        }
        return ((i * 32) + 32) - Integers.numberOfLeadingZeros(iArr[i] ^ i2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getBitLengthPositive(int i, int[] iArr) {
        while (i > 0 && iArr[i] == 0) {
            i--;
        }
        return ((i * 32) + 32) - Integers.numberOfLeadingZeros(iArr[i]);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean lessThan(int i, int[] iArr, int[] iArr2) {
        do {
            int i2 = iArr[i] - 2147483648;
            int i3 = iArr2[i] - 2147483648;
            if (i2 < i3) {
                return true;
            }
            if (i2 > i3) {
                return false;
            }
            i--;
        } while (i >= 0);
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void subShifted_NP(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int[] iArr5 = iArr4;
        int i3 = 0;
        long j = 0;
        if (i2 == 0) {
            long j2 = 0;
            while (i3 <= i) {
                long j3 = iArr3[i3] & 4294967295L;
                long j4 = (j2 + j3) - (iArr2[i3] & 4294967295L);
                int i4 = (int) j4;
                j2 = j4 >> 32;
                iArr3[i3] = i4;
                long j5 = ((j + (iArr[i3] & 4294967295L)) - j3) - (i4 & 4294967295L);
                iArr[i3] = (int) j5;
                j = j5 >> 32;
                i3++;
            }
        } else if (i2 < 32) {
            int i5 = 0;
            long j6 = 0;
            long j7 = 0;
            int i6 = 0;
            int i7 = 0;
            while (i3 <= i) {
                int i8 = iArr3[i3];
                int i9 = -i2;
                long j8 = (j6 + (iArr[i3] & 4294967295L)) - (((i5 >>> i9) | (i8 << i2)) & 4294967295L);
                int i10 = iArr2[i3];
                long j9 = (j7 + (i8 & 4294967295L)) - (((i6 >>> i9) | (i10 << i2)) & 4294967295L);
                int i11 = (int) j9;
                j7 = j9 >> 32;
                iArr3[i3] = i11;
                long j10 = j8 - (((i7 >>> i9) | (i11 << i2)) & 4294967295L);
                iArr[i3] = (int) j10;
                j6 = j10 >> 32;
                i3++;
                i7 = i11;
                i6 = i10;
                i5 = i8;
            }
        } else {
            System.arraycopy(iArr3, 0, iArr5, 0, i);
            int i12 = i2 >>> 5;
            int i13 = i2 & 31;
            if (i13 == 0) {
                long j11 = 0;
                for (int i14 = i12; i14 <= i; i14++) {
                    int i15 = i14 - i12;
                    long j12 = (j11 + (iArr3[i14] & 4294967295L)) - (iArr2[i15] & 4294967295L);
                    iArr3[i14] = (int) j12;
                    j11 = j12 >> 32;
                    long j13 = ((j + (iArr[i14] & 4294967295L)) - (iArr5[i15] & 4294967295L)) - (iArr3[i15] & 4294967295L);
                    iArr[i14] = (int) j13;
                    j = j13 >> 32;
                }
                return;
            }
            int i16 = i12;
            long j14 = 0;
            long j15 = 0;
            int i17 = 0;
            int i18 = 0;
            while (i16 <= i) {
                int i19 = i16 - i12;
                int i20 = iArr5[i19];
                int i21 = -i13;
                int i22 = i12;
                long j16 = (j14 + (iArr[i16] & 4294967295L)) - (((i20 << i13) | (i3 >>> i21)) & 4294967295L);
                int i23 = iArr2[i19];
                long j17 = (j15 + (iArr3[i16] & 4294967295L)) - (((i23 << i13) | (i17 >>> i21)) & 4294967295L);
                iArr3[i16] = (int) j17;
                j15 = j17 >> 32;
                int i24 = iArr3[i19];
                long j18 = j16 - (((i18 >>> i21) | (i24 << i13)) & 4294967295L);
                iArr[i16] = (int) j18;
                j14 = j18 >> 32;
                i16++;
                iArr5 = iArr4;
                i18 = i24;
                i17 = i23;
                i3 = i20;
                i12 = i22;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void subShifted_UV(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int i3 = i;
        int i4 = i2 >>> 5;
        int i5 = i2 & 31;
        long j = 0;
        if (i5 == 0) {
            long j2 = 0;
            for (int i6 = i4; i6 <= i3; i6++) {
                int i7 = i6 - i4;
                long j3 = (j + (iArr[i6] & 4294967295L)) - (iArr3[i7] & 4294967295L);
                long j4 = (j2 + (iArr2[i6] & 4294967295L)) - (iArr4[i7] & 4294967295L);
                iArr[i6] = (int) j3;
                j = j3 >> 32;
                iArr2[i6] = (int) j4;
                j2 = j4 >> 32;
            }
            return;
        }
        int i8 = i4;
        int i9 = 0;
        int i10 = 0;
        long j5 = 0;
        while (i8 <= i3) {
            int i11 = i8 - i4;
            int i12 = iArr3[i11];
            int i13 = iArr4[i11];
            int i14 = -i5;
            long j6 = (j + (iArr[i8] & 4294967295L)) - (((i9 >>> i14) | (i12 << i5)) & 4294967295L);
            long j7 = (j5 + (iArr2[i8] & 4294967295L)) - (((i10 >>> i14) | (i13 << i5)) & 4294967295L);
            iArr[i8] = (int) j6;
            j = j6 >> 32;
            iArr2[i8] = (int) j7;
            j5 = j7 >> 32;
            i8++;
            i10 = i13;
            i9 = i12;
            i4 = i4;
            i3 = i;
        }
    }
}