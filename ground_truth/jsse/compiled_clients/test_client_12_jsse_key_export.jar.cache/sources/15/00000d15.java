package org.bouncycastle.math.raw;

import java.util.Random;
import org.bouncycastle.util.Integers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/raw/Mod.class */
public abstract class Mod {
    private static final int M30 = 1073741823;
    private static final long M32L = 4294967295L;

    public static void checkedModOddInverse(int[] iArr, int[] iArr2, int[] iArr3) {
        if (0 == modOddInverse(iArr, iArr2, iArr3)) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static void checkedModOddInverseVar(int[] iArr, int[] iArr2, int[] iArr3) {
        if (!modOddInverseVar(iArr, iArr2, iArr3)) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static int inverse32(int i) {
        int i2 = i * (2 - (i * i));
        int i3 = i2 * (2 - (i * i2));
        int i4 = i3 * (2 - (i * i3));
        return i4 * (2 - (i * i4));
    }

    public static int modOddInverse(int[] iArr, int[] iArr2, int[] iArr3) {
        int length = iArr.length;
        int numberOfLeadingZeros = (length << 5) - Integers.numberOfLeadingZeros(iArr[length - 1]);
        int i = (numberOfLeadingZeros + 29) / 30;
        int[] iArr4 = new int[4];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        int[] iArr7 = new int[i];
        int[] iArr8 = new int[i];
        int[] iArr9 = new int[i];
        iArr6[0] = 1;
        encode30(numberOfLeadingZeros, iArr2, 0, iArr8, 0);
        encode30(numberOfLeadingZeros, iArr, 0, iArr9, 0);
        System.arraycopy(iArr9, 0, iArr7, 0, i);
        int i2 = -1;
        int inverse32 = inverse32(iArr9[0]);
        int maximumDivsteps = getMaximumDivsteps(numberOfLeadingZeros);
        for (int i3 = 0; i3 < maximumDivsteps; i3 += 30) {
            i2 = divsteps30(i2, iArr7[0], iArr8[0], iArr4);
            updateDE30(i, iArr5, iArr6, iArr4, inverse32, iArr9);
            updateFG30(i, iArr7, iArr8, iArr4);
        }
        int i4 = iArr7[i - 1] >> 31;
        cnegate30(i, i4, iArr7);
        cnormalize30(i, i4, iArr5, iArr9);
        decode30(numberOfLeadingZeros, iArr5, 0, iArr3, 0);
        return Nat.equalTo(i, iArr7, 1) & Nat.equalToZero(i, iArr8);
    }

    public static boolean modOddInverseVar(int[] iArr, int[] iArr2, int[] iArr3) {
        int length = iArr.length;
        int numberOfLeadingZeros = (length << 5) - Integers.numberOfLeadingZeros(iArr[length - 1]);
        int i = (numberOfLeadingZeros + 29) / 30;
        int[] iArr4 = new int[4];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        int[] iArr7 = new int[i];
        int[] iArr8 = new int[i];
        int[] iArr9 = new int[i];
        iArr6[0] = 1;
        encode30(numberOfLeadingZeros, iArr2, 0, iArr8, 0);
        encode30(numberOfLeadingZeros, iArr, 0, iArr9, 0);
        System.arraycopy(iArr9, 0, iArr7, 0, i);
        int numberOfLeadingZeros2 = (-1) - (Integers.numberOfLeadingZeros(iArr8[i - 1] | 1) - (((i * 30) + 2) - numberOfLeadingZeros));
        int i2 = i;
        int inverse32 = inverse32(iArr9[0]);
        int maximumDivsteps = getMaximumDivsteps(numberOfLeadingZeros);
        int i3 = 0;
        while (!Nat.isZero(i2, iArr8)) {
            if (i3 >= maximumDivsteps) {
                return false;
            }
            i3 += 30;
            numberOfLeadingZeros2 = divsteps30Var(numberOfLeadingZeros2, iArr7[0], iArr8[0], iArr4);
            updateDE30(i, iArr5, iArr6, iArr4, inverse32, iArr9);
            updateFG30(i2, iArr7, iArr8, iArr4);
            int i4 = iArr7[i2 - 1];
            int i5 = iArr8[i2 - 1];
            if ((((i2 - 2) >> 31) | (i4 ^ (i4 >> 31)) | (i5 ^ (i5 >> 31))) == 0) {
                int i6 = i2 - 2;
                iArr7[i6] = iArr7[i6] | (i4 << 30);
                int i7 = i2 - 2;
                iArr8[i7] = iArr8[i7] | (i5 << 30);
                i2--;
            }
        }
        int i8 = iArr7[i2 - 1] >> 31;
        int i9 = iArr5[i - 1] >> 31;
        if (i9 < 0) {
            i9 = add30(i, iArr5, iArr9);
        }
        if (i8 < 0) {
            i9 = negate30(i, iArr5);
            negate30(i2, iArr7);
        }
        if (Nat.isOne(i2, iArr7)) {
            if (i9 < 0) {
                add30(i, iArr5, iArr9);
            }
            decode30(numberOfLeadingZeros, iArr5, 0, iArr3, 0);
            return true;
        }
        return false;
    }

    public static int[] random(int[] iArr) {
        int length = iArr.length;
        Random random = new Random();
        int[] create = Nat.create(length);
        int i = iArr[length - 1];
        int i2 = i | (i >>> 1);
        int i3 = i2 | (i2 >>> 2);
        int i4 = i3 | (i3 >>> 4);
        int i5 = i4 | (i4 >>> 8);
        int i6 = i5 | (i5 >>> 16);
        do {
            for (int i7 = 0; i7 != length; i7++) {
                create[i7] = random.nextInt();
            }
            int i8 = length - 1;
            create[i8] = create[i8] & i6;
        } while (Nat.gte(length, create, iArr));
        return create;
    }

    private static int add30(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        int i3 = i - 1;
        for (int i4 = 0; i4 < i3; i4++) {
            int i5 = i2 + iArr[i4] + iArr2[i4];
            iArr[i4] = i5 & M30;
            i2 = i5 >> 30;
        }
        int i6 = i2 + iArr[i3] + iArr2[i3];
        iArr[i3] = i6;
        return i6 >> 30;
    }

    private static void cnegate30(int i, int i2, int[] iArr) {
        int i3 = 0;
        int i4 = i - 1;
        for (int i5 = 0; i5 < i4; i5++) {
            int i6 = i3 + ((iArr[i5] ^ i2) - i2);
            iArr[i5] = i6 & M30;
            i3 = i6 >> 30;
        }
        iArr[i4] = i3 + ((iArr[i4] ^ i2) - i2);
    }

    private static void cnormalize30(int i, int i2, int[] iArr, int[] iArr2) {
        int i3 = i - 1;
        int i4 = 0;
        int i5 = iArr[i3] >> 31;
        for (int i6 = 0; i6 < i3; i6++) {
            int i7 = i4 + (((iArr[i6] + (iArr2[i6] & i5)) ^ i2) - i2);
            iArr[i6] = i7 & M30;
            i4 = i7 >> 30;
        }
        iArr[i3] = i4 + (((iArr[i3] + (iArr2[i3] & i5)) ^ i2) - i2);
        int i8 = 0;
        int i9 = iArr[i3] >> 31;
        for (int i10 = 0; i10 < i3; i10++) {
            int i11 = i8 + iArr[i10] + (iArr2[i10] & i9);
            iArr[i10] = i11 & M30;
            i8 = i11 >> 30;
        }
        iArr[i3] = i8 + iArr[i3] + (iArr2[i3] & i9);
    }

    private static void decode30(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        int i4 = 0;
        long j = 0;
        while (i > 0) {
            while (i4 < Math.min(32, i)) {
                int i5 = i2;
                i2++;
                j |= iArr[i5] << i4;
                i4 += 30;
            }
            int i6 = i3;
            i3++;
            iArr2[i6] = (int) j;
            j >>>= 32;
            i4 -= 32;
            i -= 32;
        }
    }

    private static int divsteps30(int i, int i2, int i3, int[] iArr) {
        int i4 = 1;
        int i5 = 0;
        int i6 = 0;
        int i7 = 1;
        int i8 = i2;
        int i9 = i3;
        for (int i10 = 0; i10 < 30; i10++) {
            int i11 = i >> 31;
            int i12 = -(i9 & 1);
            int i13 = (i8 ^ i11) - i11;
            int i14 = (i4 ^ i11) - i11;
            int i15 = (i5 ^ i11) - i11;
            int i16 = i9 + (i13 & i12);
            i6 += i14 & i12;
            i7 += i15 & i12;
            int i17 = i11 & i12;
            i = (i ^ i17) - (i17 + 1);
            i8 += i16 & i17;
            i9 = i16 >> 1;
            i4 = (i4 + (i6 & i17)) << 1;
            i5 = (i5 + (i7 & i17)) << 1;
        }
        iArr[0] = i4;
        iArr[1] = i5;
        iArr[2] = i6;
        iArr[3] = i7;
        return i;
    }

    private static int divsteps30Var(int i, int i2, int i3, int[] iArr) {
        int i4;
        int i5;
        int i6;
        int i7 = 1;
        int i8 = 0;
        int i9 = 0;
        int i10 = 1;
        int i11 = i2;
        int i12 = i3;
        int i13 = 30;
        while (true) {
            int numberOfTrailingZeros = Integers.numberOfTrailingZeros(i12 | ((-1) << i13));
            int i14 = i12 >> numberOfTrailingZeros;
            i7 <<= numberOfTrailingZeros;
            i8 <<= numberOfTrailingZeros;
            i -= numberOfTrailingZeros;
            i13 -= numberOfTrailingZeros;
            if (i13 <= 0) {
                iArr[0] = i7;
                iArr[1] = i8;
                iArr[2] = i9;
                iArr[3] = i10;
                return i;
            }
            if (i < 0) {
                i = -i;
                int i15 = i11;
                i11 = i14;
                i14 = -i15;
                i7 = i9;
                i9 = -i7;
                i8 = i10;
                i10 = -i8;
                i4 = ((-1) >>> (32 - (i + 1 > i13 ? i13 : i + 1))) & 63;
                i5 = i11 * i14;
                i6 = (i11 * i11) - 2;
            } else {
                i4 = ((-1) >>> (32 - (i + 1 > i13 ? i13 : i + 1))) & 15;
                i5 = -(i11 + (((i11 + 1) & 4) << 1));
                i6 = i14;
            }
            int i16 = (i5 * i6) & i4;
            i12 = i14 + (i11 * i16);
            i9 += i7 * i16;
            i10 += i8 * i16;
        }
    }

    private static void encode30(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        int i4 = 0;
        long j = 0;
        while (i > 0) {
            if (i4 < Math.min(30, i)) {
                int i5 = i2;
                i2++;
                j |= (iArr[i5] & M32L) << i4;
                i4 += 32;
            }
            int i6 = i3;
            i3++;
            iArr2[i6] = ((int) j) & M30;
            j >>>= 30;
            i4 -= 30;
            i -= 30;
        }
    }

    private static int getMaximumDivsteps(int i) {
        return ((49 * i) + (i < 46 ? 80 : 47)) / 17;
    }

    private static int negate30(int i, int[] iArr) {
        int i2 = 0;
        int i3 = i - 1;
        for (int i4 = 0; i4 < i3; i4++) {
            int i5 = i2 - iArr[i4];
            iArr[i4] = i5 & M30;
            i2 = i5 >> 30;
        }
        int i6 = i2 - iArr[i3];
        iArr[i3] = i6;
        return i6 >> 30;
    }

    private static void updateDE30(int i, int[] iArr, int[] iArr2, int[] iArr3, int i2, int[] iArr4) {
        int i3 = iArr3[0];
        int i4 = iArr3[1];
        int i5 = iArr3[2];
        int i6 = iArr3[3];
        int i7 = iArr[i - 1] >> 31;
        int i8 = iArr2[i - 1] >> 31;
        int i9 = (i3 & i7) + (i4 & i8);
        int i10 = (i5 & i7) + (i6 & i8);
        int i11 = iArr4[0];
        int i12 = iArr[0];
        int i13 = iArr2[0];
        long j = (i3 * i12) + (i4 * i13);
        long j2 = (i5 * i12) + (i6 * i13);
        int i14 = i9 - (((i2 * ((int) j)) + i9) & M30);
        int i15 = i10 - (((i2 * ((int) j2)) + i10) & M30);
        long j3 = (j + (i11 * i14)) >> 30;
        long j4 = (j2 + (i11 * i15)) >> 30;
        for (int i16 = 1; i16 < i; i16++) {
            int i17 = iArr4[i16];
            int i18 = iArr[i16];
            int i19 = iArr2[i16];
            long j5 = j3 + (i3 * i18) + (i4 * i19) + (i17 * i14);
            long j6 = j4 + (i5 * i18) + (i6 * i19) + (i17 * i15);
            iArr[i16 - 1] = ((int) j5) & M30;
            j3 = j5 >> 30;
            iArr2[i16 - 1] = ((int) j6) & M30;
            j4 = j6 >> 30;
        }
        iArr[i - 1] = (int) j3;
        iArr2[i - 1] = (int) j4;
    }

    private static void updateFG30(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        int i2 = iArr3[0];
        int i3 = iArr3[1];
        int i4 = iArr3[2];
        int i5 = iArr3[3];
        int i6 = iArr[0];
        int i7 = iArr2[0];
        long j = ((i2 * i6) + (i3 * i7)) >> 30;
        long j2 = ((i4 * i6) + (i5 * i7)) >> 30;
        for (int i8 = 1; i8 < i; i8++) {
            int i9 = iArr[i8];
            int i10 = iArr2[i8];
            long j3 = j + (i2 * i9) + (i3 * i10);
            long j4 = j2 + (i4 * i9) + (i5 * i10);
            iArr[i8 - 1] = ((int) j3) & M30;
            j = j3 >> 30;
            iArr2[i8 - 1] = ((int) j4) & M30;
            j2 = j4 >> 30;
        }
        iArr[i - 1] = (int) j;
        iArr2[i - 1] = (int) j2;
    }
}