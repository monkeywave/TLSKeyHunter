package org.bouncycastle.math.raw;

import java.util.Random;
import org.bouncycastle.util.Integers;

/* loaded from: classes2.dex */
public abstract class Mod {
    private static final int M30 = 1073741823;
    private static final long M32L = 4294967295L;

    private static int add30(int i, int[] iArr, int[] iArr2) {
        int i2 = i - 1;
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = i3 + iArr[i4] + iArr2[i4];
            iArr[i4] = 1073741823 & i5;
            i3 = i5 >> 30;
        }
        int i6 = i3 + iArr[i2] + iArr2[i2];
        iArr[i2] = i6;
        return i6 >> 30;
    }

    public static void checkedModOddInverse(int[] iArr, int[] iArr2, int[] iArr3) {
        if (modOddInverse(iArr, iArr2, iArr3) == 0) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    public static void checkedModOddInverseVar(int[] iArr, int[] iArr2, int[] iArr3) {
        if (!modOddInverseVar(iArr, iArr2, iArr3)) {
            throw new ArithmeticException("Inverse does not exist.");
        }
    }

    private static void cnegate30(int i, int i2, int[] iArr) {
        int i3 = i - 1;
        int i4 = 0;
        for (int i5 = 0; i5 < i3; i5++) {
            int i6 = i4 + ((iArr[i5] ^ i2) - i2);
            iArr[i5] = 1073741823 & i6;
            i4 = i6 >> 30;
        }
        iArr[i3] = i4 + ((iArr[i3] ^ i2) - i2);
    }

    private static void cnormalize30(int i, int i2, int[] iArr, int[] iArr2) {
        int i3 = i - 1;
        int i4 = iArr[i3] >> 31;
        int i5 = 0;
        for (int i6 = 0; i6 < i3; i6++) {
            int i7 = i5 + (((iArr[i6] + (iArr2[i6] & i4)) ^ i2) - i2);
            iArr[i6] = 1073741823 & i7;
            i5 = i7 >> 30;
        }
        int i8 = i5 + (((iArr[i3] + (i4 & iArr2[i3])) ^ i2) - i2);
        iArr[i3] = i8;
        int i9 = i8 >> 31;
        int i10 = 0;
        for (int i11 = 0; i11 < i3; i11++) {
            int i12 = i10 + iArr[i11] + (iArr2[i11] & i9);
            iArr[i11] = i12 & 1073741823;
            i10 = i12 >> 30;
        }
        iArr[i3] = i10 + iArr[i3] + (i9 & iArr2[i3]);
    }

    private static void decode30(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        long j = 0;
        int i3 = 0;
        int i4 = 0;
        while (i > 0) {
            while (i2 < Math.min(32, i)) {
                j |= iArr[i3] << i2;
                i2 += 30;
                i3++;
            }
            iArr2[i4] = (int) j;
            j >>>= 32;
            i2 -= 32;
            i -= 32;
            i4++;
        }
    }

    private static int divsteps30Var(int i, int i2, int i3, int[] iArr) {
        int i4;
        int i5 = i2;
        int i6 = i3;
        int i7 = 1;
        int i8 = 1;
        int i9 = 0;
        int i10 = 0;
        int i11 = 30;
        int i12 = i;
        while (true) {
            int numberOfTrailingZeros = Integers.numberOfTrailingZeros(((-1) << i11) | i6);
            int i13 = i6 >> numberOfTrailingZeros;
            i7 <<= numberOfTrailingZeros;
            i9 <<= numberOfTrailingZeros;
            i12 -= numberOfTrailingZeros;
            i11 -= numberOfTrailingZeros;
            if (i11 <= 0) {
                iArr[0] = i7;
                iArr[1] = i9;
                iArr[2] = i10;
                iArr[3] = i8;
                return i12;
            }
            if (i12 <= 0) {
                i12 = 2 - i12;
                int i14 = -i5;
                int i15 = -i7;
                int i16 = -i9;
                i4 = ((-1) >>> (32 - (i12 > i11 ? i11 : i12))) & 63 & (i13 * i14 * ((i13 * i13) - 2));
                i13 = i14;
                i5 = i13;
                int i17 = i10;
                i10 = i15;
                i7 = i17;
                int i18 = i8;
                i8 = i16;
                i9 = i18;
            } else {
                i4 = ((-1) >>> (32 - (i12 > i11 ? i11 : i12))) & 15 & (((((i5 + 1) & 4) << 1) + i5) * (-i13));
            }
            i6 = i13 + (i5 * i4);
            i10 += i7 * i4;
            i8 += i4 * i9;
        }
    }

    private static void encode30(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        long j = 0;
        int i3 = 0;
        int i4 = 0;
        while (i > 0) {
            if (i2 < Math.min(30, i)) {
                j |= (iArr[i3] & 4294967295L) << i2;
                i2 += 32;
                i3++;
            }
            iArr2[i4] = ((int) j) & 1073741823;
            j >>>= 30;
            i2 -= 30;
            i -= 30;
            i4++;
        }
    }

    private static int equalTo(int i, int[] iArr, int i2) {
        int i3 = i2 ^ iArr[0];
        for (int i4 = 1; i4 < i; i4++) {
            i3 |= iArr[i4];
        }
        return (((i3 >>> 1) | (i3 & 1)) - 1) >> 31;
    }

    private static boolean equalToVar(int i, int[] iArr, int i2) {
        int i3 = i2 ^ iArr[0];
        if (i3 != 0) {
            return false;
        }
        for (int i4 = 1; i4 < i; i4++) {
            i3 |= iArr[i4];
        }
        return i3 == 0;
    }

    private static int getMaximumDivsteps(int i) {
        return (int) (((i * 188898) + (i < 46 ? 308405 : 181188)) >>> 16);
    }

    private static int getMaximumHDDivsteps(int i) {
        return (int) (((i * 150964) + 99243) >>> 16);
    }

    private static int hddivsteps30(int i, int i2, int i3, int[] iArr) {
        int i4 = 1073741824;
        int i5 = 1073741824;
        int i6 = 0;
        int i7 = 0;
        for (int i8 = 0; i8 < 30; i8++) {
            int i9 = i >> 31;
            int i10 = -(i3 & 1);
            int i11 = i3 - ((i2 ^ i9) & i10);
            int i12 = i7 - ((i4 ^ i9) & i10);
            int i13 = i5 - ((i6 ^ i9) & i10);
            int i14 = (~i9) & i10;
            i = (i ^ i14) + 1;
            i2 += i11 & i14;
            i4 += i12 & i14;
            i6 += i14 & i13;
            i3 = i11 >> 1;
            i7 = i12 >> 1;
            i5 = i13 >> 1;
        }
        iArr[0] = i4;
        iArr[1] = i6;
        iArr[2] = i7;
        iArr[3] = i5;
        return i;
    }

    public static int inverse32(int i) {
        int i2 = (2 - (i * i)) * i;
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
        char c = 0;
        iArr6[0] = 1;
        encode30(numberOfLeadingZeros, iArr2, iArr8);
        encode30(numberOfLeadingZeros, iArr, iArr9);
        System.arraycopy(iArr9, 0, iArr7, 0, i);
        int inverse32 = inverse32(iArr9[0]);
        int maximumHDDivsteps = getMaximumHDDivsteps(numberOfLeadingZeros);
        int i2 = 0;
        int i3 = 0;
        while (i3 < maximumHDDivsteps) {
            int hddivsteps30 = hddivsteps30(i2, iArr7[c], iArr8[c], iArr4);
            updateDE30(i, iArr5, iArr6, iArr4, inverse32, iArr9);
            updateFG30(i, iArr7, iArr8, iArr4);
            i3 += 30;
            i2 = hddivsteps30;
            maximumHDDivsteps = maximumHDDivsteps;
            c = 0;
        }
        int i4 = iArr7[i - 1] >> 31;
        cnegate30(i, i4, iArr7);
        cnormalize30(i, i4, iArr5, iArr9);
        decode30(numberOfLeadingZeros, iArr5, iArr3);
        return equalTo(i, iArr7, 1) & equalTo(i, iArr8, 0);
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r16v1 */
    /* JADX WARN: Type inference failed for: r9v0 */
    /* JADX WARN: Type inference failed for: r9v1, types: [boolean, int] */
    /* JADX WARN: Type inference failed for: r9v3 */
    public static boolean modOddInverseVar(int[] iArr, int[] iArr2, int[] iArr3) {
        int length = iArr.length;
        int numberOfLeadingZeros = (length << 5) - Integers.numberOfLeadingZeros(iArr[length - 1]);
        int i = (numberOfLeadingZeros + 29) / 30;
        int bitLength = numberOfLeadingZeros - Nat.getBitLength(length, iArr2);
        int[] iArr4 = new int[4];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        int[] iArr7 = new int[i];
        int[] iArr8 = new int[i];
        int[] iArr9 = new int[i];
        ?? r9 = 0;
        boolean z = true;
        iArr6[0] = 1;
        encode30(numberOfLeadingZeros, iArr2, iArr8);
        encode30(numberOfLeadingZeros, iArr, iArr9);
        System.arraycopy(iArr9, 0, iArr7, 0, i);
        int i2 = -bitLength;
        int inverse32 = inverse32(iArr9[0]);
        int maximumDivsteps = getMaximumDivsteps(numberOfLeadingZeros);
        int i3 = i;
        while (!equalToVar(i3, iArr8, r9)) {
            if (bitLength >= maximumDivsteps) {
                return r9;
            }
            int divsteps30Var = divsteps30Var(i2, iArr7[r9], iArr8[r9], iArr4);
            int i4 = i3;
            updateDE30(i, iArr5, iArr6, iArr4, inverse32, iArr9);
            updateFG30(i4, iArr7, iArr8, iArr4);
            i3 = trimFG30(i4, iArr7, iArr8);
            i2 = divsteps30Var;
            z = true;
            r9 = r9;
            maximumDivsteps = maximumDivsteps;
            bitLength += 30;
        }
        int i5 = i3;
        boolean z2 = z;
        boolean z3 = r9;
        int i6 = iArr7[i5 - 1] >> 31;
        int i7 = iArr5[i - 1] >> 31;
        if (i7 < 0) {
            i7 = add30(i, iArr5, iArr9);
        }
        if (i6 < 0) {
            i7 = negate30(i, iArr5);
            negate30(i5, iArr7);
        }
        if (equalToVar(i5, iArr7, z2 ? 1 : 0)) {
            if (i7 < 0) {
                add30(i, iArr5, iArr9);
            }
            decode30(numberOfLeadingZeros, iArr5, iArr3);
            return z2;
        }
        return z3;
    }

    public static int modOddIsCoprime(int[] iArr, int[] iArr2) {
        int length = iArr.length;
        int numberOfLeadingZeros = (length << 5) - Integers.numberOfLeadingZeros(iArr[length - 1]);
        int i = (numberOfLeadingZeros + 29) / 30;
        int[] iArr3 = new int[4];
        int[] iArr4 = new int[i];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        encode30(numberOfLeadingZeros, iArr2, iArr5);
        encode30(numberOfLeadingZeros, iArr, iArr6);
        System.arraycopy(iArr6, 0, iArr4, 0, i);
        int maximumHDDivsteps = getMaximumHDDivsteps(numberOfLeadingZeros);
        int i2 = 0;
        for (int i3 = 0; i3 < maximumHDDivsteps; i3 += 30) {
            i2 = hddivsteps30(i2, iArr4[0], iArr5[0], iArr3);
            updateFG30(i, iArr4, iArr5, iArr3);
        }
        cnegate30(i, iArr4[i - 1] >> 31, iArr4);
        return equalTo(i, iArr5, 0) & equalTo(i, iArr4, 1);
    }

    public static boolean modOddIsCoprimeVar(int[] iArr, int[] iArr2) {
        int length = iArr.length;
        int numberOfLeadingZeros = (length << 5) - Integers.numberOfLeadingZeros(iArr[length - 1]);
        int i = (numberOfLeadingZeros + 29) / 30;
        int bitLength = numberOfLeadingZeros - Nat.getBitLength(length, iArr2);
        int[] iArr3 = new int[4];
        int[] iArr4 = new int[i];
        int[] iArr5 = new int[i];
        int[] iArr6 = new int[i];
        encode30(numberOfLeadingZeros, iArr2, iArr5);
        encode30(numberOfLeadingZeros, iArr, iArr6);
        System.arraycopy(iArr6, 0, iArr4, 0, i);
        int i2 = -bitLength;
        int maximumDivsteps = getMaximumDivsteps(numberOfLeadingZeros);
        while (!equalToVar(i, iArr5, 0)) {
            if (bitLength >= maximumDivsteps) {
                return false;
            }
            bitLength += 30;
            i2 = divsteps30Var(i2, iArr4[0], iArr5[0], iArr3);
            updateFG30(i, iArr4, iArr5, iArr3);
            i = trimFG30(i, iArr4, iArr5);
        }
        if ((iArr4[i - 1] >> 31) < 0) {
            negate30(i, iArr4);
        }
        return equalToVar(i, iArr4, 1);
    }

    private static int negate30(int i, int[] iArr) {
        int i2 = i - 1;
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            int i5 = i3 - iArr[i4];
            iArr[i4] = 1073741823 & i5;
            i3 = i5 >> 30;
        }
        int i6 = i3 - iArr[i2];
        iArr[i2] = i6;
        return i6 >> 30;
    }

    public static int[] random(int[] iArr) {
        int length = iArr.length;
        Random random = new Random();
        int[] create = Nat.create(length);
        int i = length - 1;
        int i2 = iArr[i];
        int i3 = i2 | (i2 >>> 1);
        int i4 = i3 | (i3 >>> 2);
        int i5 = i4 | (i4 >>> 4);
        int i6 = i5 | (i5 >>> 8);
        int i7 = i6 | (i6 >>> 16);
        do {
            for (int i8 = 0; i8 != length; i8++) {
                create[i8] = random.nextInt();
            }
            create[i] = create[i] & i7;
        } while (Nat.gte(length, create, iArr));
        return create;
    }

    private static int trimFG30(int i, int[] iArr, int[] iArr2) {
        int i2 = i - 1;
        int i3 = iArr[i2];
        int i4 = iArr2[i2];
        int i5 = i - 2;
        if (((i5 >> 31) | ((i3 >> 31) ^ i3) | ((i4 >> 31) ^ i4)) == 0) {
            iArr[i5] = (i3 << 30) | iArr[i5];
            iArr2[i5] = iArr2[i5] | (i4 << 30);
            return i - 1;
        }
        return i;
    }

    private static void updateDE30(int i, int[] iArr, int[] iArr2, int[] iArr3, int i2, int[] iArr4) {
        int i3 = i;
        int i4 = iArr3[0];
        int i5 = iArr3[1];
        int i6 = iArr3[2];
        int i7 = iArr3[3];
        int i8 = i3 - 1;
        int i9 = iArr[i8] >> 31;
        int i10 = iArr2[i8] >> 31;
        int i11 = (i4 & i9) + (i5 & i10);
        int i12 = (i9 & i6) + (i10 & i7);
        int i13 = iArr4[0];
        long j = i4;
        long j2 = iArr[0];
        long j3 = i5;
        long j4 = iArr2[0];
        long j5 = (j * j2) + (j3 * j4);
        long j6 = i6;
        long j7 = i7;
        long j8 = (j2 * j6) + (j4 * j7);
        long j9 = i13;
        long j10 = i11 - (((((int) j5) * i2) + i11) & 1073741823);
        int i14 = i8;
        long j11 = i12 - (((((int) j8) * i2) + i12) & 1073741823);
        long j12 = (j8 + (j9 * j11)) >> 30;
        long j13 = (j5 + (j9 * j10)) >> 30;
        int i15 = 1;
        while (i15 < i3) {
            int i16 = iArr4[i15];
            long j14 = j12;
            long j15 = iArr[i15];
            int i17 = i15;
            long j16 = iArr2[i15];
            long j17 = j11;
            long j18 = i16;
            long j19 = j13 + (j * j15) + (j3 * j16) + (j18 * j10);
            long j20 = j14 + (j15 * j6) + (j16 * j7) + (j18 * j17);
            int i18 = i17 - 1;
            iArr[i18] = ((int) j19) & 1073741823;
            j13 = j19 >> 30;
            iArr2[i18] = ((int) j20) & 1073741823;
            j12 = j20 >> 30;
            i15 = i17 + 1;
            i3 = i;
            i14 = i14;
            j11 = j17;
        }
        int i19 = i14;
        iArr[i19] = (int) j13;
        iArr2[i19] = (int) j12;
    }

    private static void updateFG30(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        int i2 = iArr3[0];
        int i3 = 1;
        int i4 = iArr3[1];
        int i5 = iArr3[2];
        int i6 = iArr3[3];
        long j = i2;
        long j2 = iArr[0];
        long j3 = i4;
        long j4 = iArr2[0];
        long j5 = i5;
        long j6 = i6;
        long j7 = ((j * j2) + (j3 * j4)) >> 30;
        long j8 = ((j2 * j5) + (j4 * j6)) >> 30;
        int i7 = 1;
        while (i7 < i) {
            int i8 = iArr[i7];
            int i9 = iArr2[i7];
            int i10 = i7;
            long j9 = i8;
            long j10 = j * j9;
            long j11 = j;
            long j12 = i9;
            long j13 = j7 + j10 + (j3 * j12);
            long j14 = j8 + (j9 * j5) + (j12 * j6);
            int i11 = i10 - 1;
            iArr[i11] = ((int) j13) & 1073741823;
            j7 = j13 >> 30;
            iArr2[i11] = 1073741823 & ((int) j14);
            j8 = j14 >> 30;
            i7 = i10 + 1;
            j = j11;
            i3 = 1;
        }
        int i12 = i - i3;
        iArr[i12] = (int) j7;
        iArr2[i12] = (int) j8;
    }
}