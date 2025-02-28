package org.bouncycastle.math.raw;

import java.math.BigInteger;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/raw/Nat.class */
public abstract class Nat {

    /* renamed from: M */
    private static final long f790M = 4294967295L;

    public static int add(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + (iArr[i2] & f790M) + (iArr2[i2] & f790M);
            iArr3[i2] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int add33At(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3 + 0] & f790M) + (i2 & f790M);
        iArr[i3 + 0] = (int) j;
        long j2 = (j >>> 32) + (iArr[i3 + 1] & f790M) + 1;
        iArr[i3 + 1] = (int) j2;
        if ((j2 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3 + 2);
    }

    public static int add33At(int i, int i2, int[] iArr, int i3, int i4) {
        long j = (iArr[i3 + i4] & f790M) + (i2 & f790M);
        iArr[i3 + i4] = (int) j;
        long j2 = (j >>> 32) + (iArr[i3 + i4 + 1] & f790M) + 1;
        iArr[i3 + i4 + 1] = (int) j2;
        if ((j2 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3, i4 + 2);
    }

    public static int add33To(int i, int i2, int[] iArr) {
        long j = (iArr[0] & f790M) + (i2 & f790M);
        iArr[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & f790M) + 1;
        iArr[1] = (int) j2;
        if ((j2 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, 2);
    }

    public static int add33To(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3 + 0] & f790M) + (i2 & f790M);
        iArr[i3 + 0] = (int) j;
        long j2 = (j >>> 32) + (iArr[i3 + 1] & f790M) + 1;
        iArr[i3 + 1] = (int) j2;
        if ((j2 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3, 2);
    }

    public static int addBothTo(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + (iArr[i2] & f790M) + (iArr2[i2] & f790M) + (iArr3[i2] & f790M);
            iArr3[i2] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addBothTo(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = 0;
        for (int i5 = 0; i5 < i; i5++) {
            long j2 = j + (iArr[i2 + i5] & f790M) + (iArr2[i3 + i5] & f790M) + (iArr3[i4 + i5] & f790M);
            iArr3[i4 + i5] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addDWordAt(int i, long j, int[] iArr, int i2) {
        long j2 = (iArr[i2 + 0] & f790M) + (j & f790M);
        iArr[i2 + 0] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i2 + 1] & f790M) + (j >>> 32);
        iArr[i2 + 1] = (int) j3;
        if ((j3 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i2 + 2);
    }

    public static int addDWordAt(int i, long j, int[] iArr, int i2, int i3) {
        long j2 = (iArr[i2 + i3] & f790M) + (j & f790M);
        iArr[i2 + i3] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i2 + i3 + 1] & f790M) + (j >>> 32);
        iArr[i2 + i3 + 1] = (int) j3;
        if ((j3 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i2, i3 + 2);
    }

    public static int addDWordTo(int i, long j, int[] iArr) {
        long j2 = (iArr[0] & f790M) + (j & f790M);
        iArr[0] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[1] & f790M) + (j >>> 32);
        iArr[1] = (int) j3;
        if ((j3 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, 2);
    }

    public static int addDWordTo(int i, long j, int[] iArr, int i2) {
        long j2 = (iArr[i2 + 0] & f790M) + (j & f790M);
        iArr[i2 + 0] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i2 + 1] & f790M) + (j >>> 32);
        iArr[i2 + 1] = (int) j3;
        if ((j3 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i2, 2);
    }

    public static int addTo(int i, int[] iArr, int[] iArr2) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + (iArr[i2] & f790M) + (iArr2[i2] & f790M);
            iArr2[i2] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addTo(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = 0;
        for (int i4 = 0; i4 < i; i4++) {
            long j2 = j + (iArr[i2 + i4] & f790M) + (iArr2[i3 + i4] & f790M);
            iArr2[i3 + i4] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addTo(int i, int[] iArr, int i2, int[] iArr2, int i3, int i4) {
        long j = i4 & f790M;
        for (int i5 = 0; i5 < i; i5++) {
            long j2 = j + (iArr[i2 + i5] & f790M) + (iArr2[i3 + i5] & f790M);
            iArr2[i3 + i5] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addToEachOther(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = 0;
        for (int i4 = 0; i4 < i; i4++) {
            long j2 = j + (iArr[i2 + i4] & f790M) + (iArr2[i3 + i4] & f790M);
            iArr[i2 + i4] = (int) j2;
            iArr2[i3 + i4] = (int) j2;
            j = j2 >>> 32;
        }
        return (int) j;
    }

    public static int addWordAt(int i, int i2, int[] iArr, int i3) {
        long j = (i2 & f790M) + (iArr[i3] & f790M);
        iArr[i3] = (int) j;
        if ((j >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3 + 1);
    }

    public static int addWordAt(int i, int i2, int[] iArr, int i3, int i4) {
        long j = (i2 & f790M) + (iArr[i3 + i4] & f790M);
        iArr[i3 + i4] = (int) j;
        if ((j >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3, i4 + 1);
    }

    public static int addWordTo(int i, int i2, int[] iArr) {
        long j = (i2 & f790M) + (iArr[0] & f790M);
        iArr[0] = (int) j;
        if ((j >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, 1);
    }

    public static int addWordTo(int i, int i2, int[] iArr, int i3) {
        long j = (i2 & f790M) + (iArr[i3] & f790M);
        iArr[i3] = (int) j;
        if ((j >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3, 1);
    }

    public static int cadd(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = (-(i2 & 1)) & f790M;
        long j2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            long j3 = j2 + (iArr[i3] & f790M) + (iArr2[i3] & j);
            iArr3[i3] = (int) j3;
            j2 = j3 >>> 32;
        }
        return (int) j2;
    }

    public static void cmov(int i, int i2, int[] iArr, int i3, int[] iArr2, int i4) {
        int i5 = -(i2 & 1);
        for (int i6 = 0; i6 < i; i6++) {
            int i7 = iArr2[i4 + i6];
            iArr2[i4 + i6] = i7 ^ ((i7 ^ iArr[i3 + i6]) & i5);
        }
    }

    public static int compare(int i, int[] iArr, int[] iArr2) {
        for (int i2 = i - 1; i2 >= 0; i2--) {
            int i3 = iArr[i2] ^ Integer.MIN_VALUE;
            int i4 = iArr2[i2] ^ Integer.MIN_VALUE;
            if (i3 < i4) {
                return -1;
            }
            if (i3 > i4) {
                return 1;
            }
        }
        return 0;
    }

    public static int compare(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        for (int i4 = i - 1; i4 >= 0; i4--) {
            int i5 = iArr[i2 + i4] ^ Integer.MIN_VALUE;
            int i6 = iArr2[i3 + i4] ^ Integer.MIN_VALUE;
            if (i5 < i6) {
                return -1;
            }
            if (i5 > i6) {
                return 1;
            }
        }
        return 0;
    }

    public static int[] copy(int i, int[] iArr) {
        int[] iArr2 = new int[i];
        System.arraycopy(iArr, 0, iArr2, 0, i);
        return iArr2;
    }

    public static void copy(int i, int[] iArr, int[] iArr2) {
        System.arraycopy(iArr, 0, iArr2, 0, i);
    }

    public static void copy(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        System.arraycopy(iArr, i2, iArr2, i3, i);
    }

    public static long[] copy64(int i, long[] jArr) {
        long[] jArr2 = new long[i];
        System.arraycopy(jArr, 0, jArr2, 0, i);
        return jArr2;
    }

    public static void copy64(int i, long[] jArr, long[] jArr2) {
        System.arraycopy(jArr, 0, jArr2, 0, i);
    }

    public static void copy64(int i, long[] jArr, int i2, long[] jArr2, int i3) {
        System.arraycopy(jArr, i2, jArr2, i3, i);
    }

    public static int[] create(int i) {
        return new int[i];
    }

    public static long[] create64(int i) {
        return new long[i];
    }

    public static int csub(int i, int i2, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = (-(i2 & 1)) & f790M;
        long j2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            long j3 = j2 + ((iArr[i3] & f790M) - (iArr2[i3] & j));
            iArr3[i3] = (int) j3;
            j2 = j3 >> 32;
        }
        return (int) j2;
    }

    public static int csub(int i, int i2, int[] iArr, int i3, int[] iArr2, int i4, int[] iArr3, int i5) {
        long j = (-(i2 & 1)) & f790M;
        long j2 = 0;
        for (int i6 = 0; i6 < i; i6++) {
            long j3 = j2 + ((iArr[i3 + i6] & f790M) - (iArr2[i4 + i6] & j));
            iArr3[i5 + i6] = (int) j3;
            j2 = j3 >> 32;
        }
        return (int) j2;
    }

    public static int dec(int i, int[] iArr) {
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = i2;
            int i4 = iArr[i3] - 1;
            iArr[i3] = i4;
            if (i4 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static int dec(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        while (i2 < i) {
            int i3 = iArr[i2] - 1;
            iArr2[i2] = i3;
            i2++;
            if (i3 != -1) {
                while (i2 < i) {
                    iArr2[i2] = iArr[i2];
                    i2++;
                }
                return 0;
            }
        }
        return -1;
    }

    public static int decAt(int i, int[] iArr, int i2) {
        for (int i3 = i2; i3 < i; i3++) {
            int i4 = i3;
            int i5 = iArr[i4] - 1;
            iArr[i4] = i5;
            if (i5 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static int decAt(int i, int[] iArr, int i2, int i3) {
        for (int i4 = i3; i4 < i; i4++) {
            int i5 = i2 + i4;
            int i6 = iArr[i5] - 1;
            iArr[i5] = i6;
            if (i6 != -1) {
                return 0;
            }
        }
        return -1;
    }

    public static boolean diff(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        boolean gte = gte(i, iArr, i2, iArr2, i3);
        if (gte) {
            sub(i, iArr, i2, iArr2, i3, iArr3, i4);
        } else {
            sub(i, iArr2, i3, iArr, i2, iArr3, i4);
        }
        return gte;
    }

    /* renamed from: eq */
    public static boolean m19eq(int i, int[] iArr, int[] iArr2) {
        for (int i2 = i - 1; i2 >= 0; i2--) {
            if (iArr[i2] != iArr2[i2]) {
                return false;
            }
        }
        return true;
    }

    public static int equalTo(int i, int[] iArr, int i2) {
        int i3 = iArr[0] ^ i2;
        for (int i4 = 1; i4 < i; i4++) {
            i3 |= iArr[i4];
        }
        return (((i3 >>> 1) | (i3 & 1)) - 1) >> 31;
    }

    public static int equalTo(int i, int[] iArr, int i2, int i3) {
        int i4 = iArr[i2] ^ i3;
        for (int i5 = 1; i5 < i; i5++) {
            i4 |= iArr[i2 + i5];
        }
        return (((i4 >>> 1) | (i4 & 1)) - 1) >> 31;
    }

    public static int equalTo(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            i2 |= iArr[i3] ^ iArr2[i3];
        }
        return (((i2 >>> 1) | (i2 & 1)) - 1) >> 31;
    }

    public static int equalTo(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        int i4 = 0;
        for (int i5 = 0; i5 < i; i5++) {
            i4 |= iArr[i2 + i5] ^ iArr2[i3 + i5];
        }
        return (((i4 >>> 1) | (i4 & 1)) - 1) >> 31;
    }

    public static int equalToZero(int i, int[] iArr) {
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            i2 |= iArr[i3];
        }
        return (((i2 >>> 1) | (i2 & 1)) - 1) >> 31;
    }

    public static int equalToZero(int i, int[] iArr, int i2) {
        int i3 = 0;
        for (int i4 = 0; i4 < i; i4++) {
            i3 |= iArr[i2 + i4];
        }
        return (((i3 >>> 1) | (i3 & 1)) - 1) >> 31;
    }

    public static int[] fromBigInteger(int i, BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > i) {
            throw new IllegalArgumentException();
        }
        int i2 = (i + 31) >> 5;
        int[] create = create(i2);
        for (int i3 = 0; i3 < i2; i3++) {
            create[i3] = bigInteger.intValue();
            bigInteger = bigInteger.shiftRight(32);
        }
        return create;
    }

    public static long[] fromBigInteger64(int i, BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > i) {
            throw new IllegalArgumentException();
        }
        int i2 = (i + 63) >> 6;
        long[] create64 = create64(i2);
        for (int i3 = 0; i3 < i2; i3++) {
            create64[i3] = bigInteger.longValue();
            bigInteger = bigInteger.shiftRight(64);
        }
        return create64;
    }

    public static int getBit(int[] iArr, int i) {
        if (i == 0) {
            return iArr[0] & 1;
        }
        int i2 = i >> 5;
        if (i2 < 0 || i2 >= iArr.length) {
            return 0;
        }
        return (iArr[i2] >>> (i & 31)) & 1;
    }

    public static boolean gte(int i, int[] iArr, int[] iArr2) {
        for (int i2 = i - 1; i2 >= 0; i2--) {
            int i3 = iArr[i2] ^ Integer.MIN_VALUE;
            int i4 = iArr2[i2] ^ Integer.MIN_VALUE;
            if (i3 < i4) {
                return false;
            }
            if (i3 > i4) {
                return true;
            }
        }
        return true;
    }

    public static boolean gte(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        for (int i4 = i - 1; i4 >= 0; i4--) {
            int i5 = iArr[i2 + i4] ^ Integer.MIN_VALUE;
            int i6 = iArr2[i3 + i4] ^ Integer.MIN_VALUE;
            if (i5 < i6) {
                return false;
            }
            if (i5 > i6) {
                return true;
            }
        }
        return true;
    }

    public static int inc(int i, int[] iArr) {
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = i2;
            int i4 = iArr[i3] + 1;
            iArr[i3] = i4;
            if (i4 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static int inc(int i, int[] iArr, int[] iArr2) {
        int i2 = 0;
        while (i2 < i) {
            int i3 = iArr[i2] + 1;
            iArr2[i2] = i3;
            i2++;
            if (i3 != 0) {
                while (i2 < i) {
                    iArr2[i2] = iArr[i2];
                    i2++;
                }
                return 0;
            }
        }
        return 1;
    }

    public static int incAt(int i, int[] iArr, int i2) {
        for (int i3 = i2; i3 < i; i3++) {
            int i4 = i3;
            int i5 = iArr[i4] + 1;
            iArr[i4] = i5;
            if (i5 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static int incAt(int i, int[] iArr, int i2, int i3) {
        for (int i4 = i3; i4 < i; i4++) {
            int i5 = i2 + i4;
            int i6 = iArr[i5] + 1;
            iArr[i5] = i6;
            if (i6 != 0) {
                return 0;
            }
        }
        return 1;
    }

    public static boolean isOne(int i, int[] iArr) {
        if (iArr[0] != 1) {
            return false;
        }
        for (int i2 = 1; i2 < i; i2++) {
            if (iArr[i2] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int i, int[] iArr) {
        for (int i2 = 0; i2 < i; i2++) {
            if (iArr[i2] != 0) {
                return false;
            }
        }
        return true;
    }

    public static int lessThan(int i, int[] iArr, int[] iArr2) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            j = (j + ((iArr[i2] & f790M) - (iArr2[i2] & f790M))) >> 32;
        }
        return (int) j;
    }

    public static int lessThan(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = 0;
        for (int i4 = 0; i4 < i; i4++) {
            j = (j + ((iArr[i2 + i4] & f790M) - (iArr2[i3 + i4] & f790M))) >> 32;
        }
        return (int) j;
    }

    public static void mul(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        iArr3[i] = mulWord(i, iArr[0], iArr2, iArr3);
        for (int i2 = 1; i2 < i; i2++) {
            iArr3[i2 + i] = mulWordAddTo(i, iArr[i2], iArr2, 0, iArr3, i2);
        }
    }

    public static void mul(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        iArr3[i4 + i] = mulWord(i, iArr[i2], iArr2, i3, iArr3, i4);
        for (int i5 = 1; i5 < i; i5++) {
            iArr3[i4 + i5 + i] = mulWordAddTo(i, iArr[i2 + i5], iArr2, i3, iArr3, i4 + i5);
        }
    }

    public static void mul(int[] iArr, int i, int i2, int[] iArr2, int i3, int i4, int[] iArr3, int i5) {
        iArr3[i5 + i4] = mulWord(i4, iArr[i], iArr2, i3, iArr3, i5);
        for (int i6 = 1; i6 < i2; i6++) {
            iArr3[i5 + i6 + i4] = mulWordAddTo(i4, iArr[i + i6], iArr2, i3, iArr3, i5 + i6);
        }
    }

    public static int mulAddTo(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long mulWordAddTo = j + (mulWordAddTo(i, iArr[i2], iArr2, 0, iArr3, i2) & f790M) + (iArr3[i2 + i] & f790M);
            iArr3[i2 + i] = (int) mulWordAddTo;
            j = mulWordAddTo >>> 32;
        }
        return (int) j;
    }

    public static int mulAddTo(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = 0;
        for (int i5 = 0; i5 < i; i5++) {
            long mulWordAddTo = j + (mulWordAddTo(i, iArr[i2 + i5], iArr2, i3, iArr3, i4) & f790M) + (iArr3[i4 + i] & f790M);
            iArr3[i4 + i] = (int) mulWordAddTo;
            j = mulWordAddTo >>> 32;
            i4++;
        }
        return (int) j;
    }

    public static int mul31BothAdd(int i, int i2, int[] iArr, int i3, int[] iArr2, int[] iArr3, int i4) {
        long j = 0;
        long j2 = i2 & f790M;
        long j3 = i3 & f790M;
        int i5 = 0;
        do {
            long j4 = j + (j2 * (iArr[i5] & f790M)) + (j3 * (iArr2[i5] & f790M)) + (iArr3[i4 + i5] & f790M);
            iArr3[i4 + i5] = (int) j4;
            j = j4 >>> 32;
            i5++;
        } while (i5 < i);
        return (int) j;
    }

    public static int mulWord(int i, int i2, int[] iArr, int[] iArr2) {
        long j = 0;
        long j2 = i2 & f790M;
        int i3 = 0;
        do {
            long j3 = j + (j2 * (iArr[i3] & f790M));
            iArr2[i3] = (int) j3;
            j = j3 >>> 32;
            i3++;
        } while (i3 < i);
        return (int) j;
    }

    public static int mulWord(int i, int i2, int[] iArr, int i3, int[] iArr2, int i4) {
        long j = 0;
        long j2 = i2 & f790M;
        int i5 = 0;
        do {
            long j3 = j + (j2 * (iArr[i3 + i5] & f790M));
            iArr2[i4 + i5] = (int) j3;
            j = j3 >>> 32;
            i5++;
        } while (i5 < i);
        return (int) j;
    }

    public static int mulWordAddTo(int i, int i2, int[] iArr, int i3, int[] iArr2, int i4) {
        long j = 0;
        long j2 = i2 & f790M;
        int i5 = 0;
        do {
            long j3 = j + (j2 * (iArr[i3 + i5] & f790M)) + (iArr2[i4 + i5] & f790M);
            iArr2[i4 + i5] = (int) j3;
            j = j3 >>> 32;
            i5++;
        } while (i5 < i);
        return (int) j;
    }

    public static int mulWordDwordAddAt(int i, int i2, long j, int[] iArr, int i3) {
        long j2 = i2 & f790M;
        long j3 = 0 + (j2 * (j & f790M)) + (iArr[i3 + 0] & f790M);
        iArr[i3 + 0] = (int) j3;
        long j4 = (j3 >>> 32) + (j2 * (j >>> 32)) + (iArr[i3 + 1] & f790M);
        iArr[i3 + 1] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[i3 + 2] & f790M);
        iArr[i3 + 2] = (int) j5;
        if ((j5 >>> 32) == 0) {
            return 0;
        }
        return incAt(i, iArr, i3 + 3);
    }

    public static int shiftDownBit(int i, int[] iArr, int i2) {
        int i3 = i;
        while (true) {
            i3--;
            if (i3 < 0) {
                return i2 << 31;
            }
            int i4 = iArr[i3];
            iArr[i3] = (i4 >>> 1) | (i2 << 31);
            i2 = i4;
        }
    }

    public static int shiftDownBit(int i, int[] iArr, int i2, int i3) {
        int i4 = i;
        while (true) {
            i4--;
            if (i4 < 0) {
                return i3 << 31;
            }
            int i5 = iArr[i2 + i4];
            iArr[i2 + i4] = (i5 >>> 1) | (i3 << 31);
            i3 = i5;
        }
    }

    public static int shiftDownBit(int i, int[] iArr, int i2, int[] iArr2) {
        int i3 = i;
        while (true) {
            i3--;
            if (i3 < 0) {
                return i2 << 31;
            }
            int i4 = iArr[i3];
            iArr2[i3] = (i4 >>> 1) | (i2 << 31);
            i2 = i4;
        }
    }

    public static int shiftDownBit(int i, int[] iArr, int i2, int i3, int[] iArr2, int i4) {
        int i5 = i;
        while (true) {
            i5--;
            if (i5 < 0) {
                return i3 << 31;
            }
            int i6 = iArr[i2 + i5];
            iArr2[i4 + i5] = (i6 >>> 1) | (i3 << 31);
            i3 = i6;
        }
    }

    public static int shiftDownBits(int i, int[] iArr, int i2, int i3) {
        int i4 = i;
        while (true) {
            i4--;
            if (i4 < 0) {
                return i3 << (-i2);
            }
            int i5 = iArr[i4];
            iArr[i4] = (i5 >>> i2) | (i3 << (-i2));
            i3 = i5;
        }
    }

    public static int shiftDownBits(int i, int[] iArr, int i2, int i3, int i4) {
        int i5 = i;
        while (true) {
            i5--;
            if (i5 < 0) {
                return i4 << (-i3);
            }
            int i6 = iArr[i2 + i5];
            iArr[i2 + i5] = (i6 >>> i3) | (i4 << (-i3));
            i4 = i6;
        }
    }

    public static int shiftDownBits(int i, int[] iArr, int i2, int i3, int[] iArr2) {
        int i4 = i;
        while (true) {
            i4--;
            if (i4 < 0) {
                return i3 << (-i2);
            }
            int i5 = iArr[i4];
            iArr2[i4] = (i5 >>> i2) | (i3 << (-i2));
            i3 = i5;
        }
    }

    public static int shiftDownBits(int i, int[] iArr, int i2, int i3, int i4, int[] iArr2, int i5) {
        int i6 = i;
        while (true) {
            i6--;
            if (i6 < 0) {
                return i4 << (-i3);
            }
            int i7 = iArr[i2 + i6];
            iArr2[i5 + i6] = (i7 >>> i3) | (i4 << (-i3));
            i4 = i7;
        }
    }

    public static int shiftDownWord(int i, int[] iArr, int i2) {
        int i3 = i;
        while (true) {
            i3--;
            if (i3 < 0) {
                return i2;
            }
            int i4 = iArr[i3];
            iArr[i3] = i2;
            i2 = i4;
        }
    }

    public static int shiftUpBit(int i, int[] iArr, int i2) {
        for (int i3 = 0; i3 < i; i3++) {
            int i4 = iArr[i3];
            iArr[i3] = (i4 << 1) | (i2 >>> 31);
            i2 = i4;
        }
        return i2 >>> 31;
    }

    public static int shiftUpBit(int i, int[] iArr, int i2, int i3) {
        for (int i4 = 0; i4 < i; i4++) {
            int i5 = iArr[i2 + i4];
            iArr[i2 + i4] = (i5 << 1) | (i3 >>> 31);
            i3 = i5;
        }
        return i3 >>> 31;
    }

    public static int shiftUpBit(int i, int[] iArr, int i2, int[] iArr2) {
        for (int i3 = 0; i3 < i; i3++) {
            int i4 = iArr[i3];
            iArr2[i3] = (i4 << 1) | (i2 >>> 31);
            i2 = i4;
        }
        return i2 >>> 31;
    }

    public static int shiftUpBit(int i, int[] iArr, int i2, int i3, int[] iArr2, int i4) {
        for (int i5 = 0; i5 < i; i5++) {
            int i6 = iArr[i2 + i5];
            iArr2[i4 + i5] = (i6 << 1) | (i3 >>> 31);
            i3 = i6;
        }
        return i3 >>> 31;
    }

    public static long shiftUpBit64(int i, long[] jArr, int i2, long j, long[] jArr2, int i3) {
        for (int i4 = 0; i4 < i; i4++) {
            long j2 = jArr[i2 + i4];
            jArr2[i3 + i4] = (j2 << 1) | (j >>> 63);
            j = j2;
        }
        return j >>> 63;
    }

    public static int shiftUpBits(int i, int[] iArr, int i2, int i3) {
        for (int i4 = 0; i4 < i; i4++) {
            int i5 = iArr[i4];
            iArr[i4] = (i5 << i2) | (i3 >>> (-i2));
            i3 = i5;
        }
        return i3 >>> (-i2);
    }

    public static int shiftUpBits(int i, int[] iArr, int i2, int i3, int i4) {
        for (int i5 = 0; i5 < i; i5++) {
            int i6 = iArr[i2 + i5];
            iArr[i2 + i5] = (i6 << i3) | (i4 >>> (-i3));
            i4 = i6;
        }
        return i4 >>> (-i3);
    }

    public static long shiftUpBits64(int i, long[] jArr, int i2, int i3, long j) {
        for (int i4 = 0; i4 < i; i4++) {
            long j2 = jArr[i2 + i4];
            jArr[i2 + i4] = (j2 << i3) | (j >>> (-i3));
            j = j2;
        }
        return j >>> (-i3);
    }

    public static int shiftUpBits(int i, int[] iArr, int i2, int i3, int[] iArr2) {
        for (int i4 = 0; i4 < i; i4++) {
            int i5 = iArr[i4];
            iArr2[i4] = (i5 << i2) | (i3 >>> (-i2));
            i3 = i5;
        }
        return i3 >>> (-i2);
    }

    public static int shiftUpBits(int i, int[] iArr, int i2, int i3, int i4, int[] iArr2, int i5) {
        for (int i6 = 0; i6 < i; i6++) {
            int i7 = iArr[i2 + i6];
            iArr2[i5 + i6] = (i7 << i3) | (i4 >>> (-i3));
            i4 = i7;
        }
        return i4 >>> (-i3);
    }

    public static long shiftUpBits64(int i, long[] jArr, int i2, int i3, long j, long[] jArr2, int i4) {
        for (int i5 = 0; i5 < i; i5++) {
            long j2 = jArr[i2 + i5];
            jArr2[i4 + i5] = (j2 << i3) | (j >>> (-i3));
            j = j2;
        }
        return j >>> (-i3);
    }

    public static void square(int i, int[] iArr, int[] iArr2) {
        int i2 = i << 1;
        int i3 = 0;
        int i4 = i;
        int i5 = i2;
        do {
            i4--;
            long j = iArr[i4] & f790M;
            long j2 = j * j;
            int i6 = i5 - 1;
            iArr2[i6] = (i3 << 31) | ((int) (j2 >>> 33));
            i5 = i6 - 1;
            iArr2[i5] = (int) (j2 >>> 1);
            i3 = (int) j2;
        } while (i4 > 0);
        long j3 = 0;
        int i7 = 2;
        for (int i8 = 1; i8 < i; i8++) {
            long squareWordAddTo = j3 + (squareWordAddTo(iArr, i8, iArr2) & f790M) + (iArr2[i7] & f790M);
            int i9 = i7;
            int i10 = i7 + 1;
            iArr2[i9] = (int) squareWordAddTo;
            long j4 = (squareWordAddTo >>> 32) + (iArr2[i10] & f790M);
            i7 = i10 + 1;
            iArr2[i10] = (int) j4;
            j3 = j4 >>> 32;
        }
        shiftUpBit(i2, iArr2, iArr[0] << 31);
    }

    public static void square(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        int i4 = i << 1;
        int i5 = 0;
        int i6 = i;
        int i7 = i4;
        do {
            i6--;
            long j = iArr[i2 + i6] & f790M;
            long j2 = j * j;
            int i8 = i7 - 1;
            iArr2[i3 + i8] = (i5 << 31) | ((int) (j2 >>> 33));
            i7 = i8 - 1;
            iArr2[i3 + i7] = (int) (j2 >>> 1);
            i5 = (int) j2;
        } while (i6 > 0);
        long j3 = 0;
        int i9 = i3 + 2;
        for (int i10 = 1; i10 < i; i10++) {
            long squareWordAddTo = j3 + (squareWordAddTo(iArr, i2, i10, iArr2, i3) & f790M) + (iArr2[i9] & f790M);
            int i11 = i9;
            int i12 = i9 + 1;
            iArr2[i11] = (int) squareWordAddTo;
            long j4 = (squareWordAddTo >>> 32) + (iArr2[i12] & f790M);
            i9 = i12 + 1;
            iArr2[i12] = (int) j4;
            j3 = j4 >>> 32;
        }
        shiftUpBit(i4, iArr2, i3, iArr[i2] << 31);
    }

    public static int squareWordAddTo(int[] iArr, int i, int[] iArr2) {
        long j = 0;
        long j2 = iArr[i] & f790M;
        int i2 = 0;
        do {
            long j3 = j + (j2 * (iArr[i2] & f790M)) + (iArr2[i + i2] & f790M);
            iArr2[i + i2] = (int) j3;
            j = j3 >>> 32;
            i2++;
        } while (i2 < i);
        return (int) j;
    }

    public static int squareWordAddTo(int[] iArr, int i, int i2, int[] iArr2, int i3) {
        long j = 0;
        long j2 = iArr[i + i2] & f790M;
        int i4 = 0;
        do {
            long j3 = j + (j2 * (iArr[i + i4] & f790M)) + (iArr2[i2 + i3] & f790M);
            iArr2[i2 + i3] = (int) j3;
            j = j3 >>> 32;
            i3++;
            i4++;
        } while (i4 < i2);
        return (int) j;
    }

    public static int sub(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + ((iArr[i2] & f790M) - (iArr2[i2] & f790M));
            iArr3[i2] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int sub(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = 0;
        for (int i5 = 0; i5 < i; i5++) {
            long j2 = j + ((iArr[i2 + i5] & f790M) - (iArr2[i3 + i5] & f790M));
            iArr3[i4 + i5] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int sub33At(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3 + 0] & f790M) - (i2 & f790M);
        iArr[i3 + 0] = (int) j;
        long j2 = (j >> 32) + ((iArr[i3 + 1] & f790M) - 1);
        iArr[i3 + 1] = (int) j2;
        if ((j2 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3 + 2);
    }

    public static int sub33At(int i, int i2, int[] iArr, int i3, int i4) {
        long j = (iArr[i3 + i4] & f790M) - (i2 & f790M);
        iArr[i3 + i4] = (int) j;
        long j2 = (j >> 32) + ((iArr[(i3 + i4) + 1] & f790M) - 1);
        iArr[i3 + i4 + 1] = (int) j2;
        if ((j2 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3, i4 + 2);
    }

    public static int sub33From(int i, int i2, int[] iArr) {
        long j = (iArr[0] & f790M) - (i2 & f790M);
        iArr[0] = (int) j;
        long j2 = (j >> 32) + ((iArr[1] & f790M) - 1);
        iArr[1] = (int) j2;
        if ((j2 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, 2);
    }

    public static int sub33From(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3 + 0] & f790M) - (i2 & f790M);
        iArr[i3 + 0] = (int) j;
        long j2 = (j >> 32) + ((iArr[i3 + 1] & f790M) - 1);
        iArr[i3 + 1] = (int) j2;
        if ((j2 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3, 2);
    }

    public static int subBothFrom(int i, int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + (((iArr3[i2] & f790M) - (iArr[i2] & f790M)) - (iArr2[i2] & f790M));
            iArr3[i2] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int subBothFrom(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = 0;
        for (int i5 = 0; i5 < i; i5++) {
            long j2 = j + (((iArr3[i4 + i5] & f790M) - (iArr[i2 + i5] & f790M)) - (iArr2[i3 + i5] & f790M));
            iArr3[i4 + i5] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int subDWordAt(int i, long j, int[] iArr, int i2) {
        long j2 = (iArr[i2 + 0] & f790M) - (j & f790M);
        iArr[i2 + 0] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[i2 + 1] & f790M) - (j >>> 32));
        iArr[i2 + 1] = (int) j3;
        if ((j3 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i2 + 2);
    }

    public static int subDWordAt(int i, long j, int[] iArr, int i2, int i3) {
        long j2 = (iArr[i2 + i3] & f790M) - (j & f790M);
        iArr[i2 + i3] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[(i2 + i3) + 1] & f790M) - (j >>> 32));
        iArr[i2 + i3 + 1] = (int) j3;
        if ((j3 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i2, i3 + 2);
    }

    public static int subDWordFrom(int i, long j, int[] iArr) {
        long j2 = (iArr[0] & f790M) - (j & f790M);
        iArr[0] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[1] & f790M) - (j >>> 32));
        iArr[1] = (int) j3;
        if ((j3 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, 2);
    }

    public static int subDWordFrom(int i, long j, int[] iArr, int i2) {
        long j2 = (iArr[i2 + 0] & f790M) - (j & f790M);
        iArr[i2 + 0] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[i2 + 1] & f790M) - (j >>> 32));
        iArr[i2 + 1] = (int) j3;
        if ((j3 >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i2, 2);
    }

    public static int subFrom(int i, int[] iArr, int[] iArr2) {
        long j = 0;
        for (int i2 = 0; i2 < i; i2++) {
            long j2 = j + ((iArr2[i2] & f790M) - (iArr[i2] & f790M));
            iArr2[i2] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int subFrom(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = 0;
        for (int i4 = 0; i4 < i; i4++) {
            long j2 = j + ((iArr2[i3 + i4] & f790M) - (iArr[i2 + i4] & f790M));
            iArr2[i3 + i4] = (int) j2;
            j = j2 >> 32;
        }
        return (int) j;
    }

    public static int subWordAt(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3] & f790M) - (i2 & f790M);
        iArr[i3] = (int) j;
        if ((j >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3 + 1);
    }

    public static int subWordAt(int i, int i2, int[] iArr, int i3, int i4) {
        long j = (iArr[i3 + i4] & f790M) - (i2 & f790M);
        iArr[i3 + i4] = (int) j;
        if ((j >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3, i4 + 1);
    }

    public static int subWordFrom(int i, int i2, int[] iArr) {
        long j = (iArr[0] & f790M) - (i2 & f790M);
        iArr[0] = (int) j;
        if ((j >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, 1);
    }

    public static int subWordFrom(int i, int i2, int[] iArr, int i3) {
        long j = (iArr[i3 + 0] & f790M) - (i2 & f790M);
        iArr[i3 + 0] = (int) j;
        if ((j >> 32) == 0) {
            return 0;
        }
        return decAt(i, iArr, i3, 1);
    }

    public static BigInteger toBigInteger(int i, int[] iArr) {
        byte[] bArr = new byte[i << 2];
        for (int i2 = 0; i2 < i; i2++) {
            int i3 = iArr[i2];
            if (i3 != 0) {
                Pack.intToBigEndian(i3, bArr, ((i - 1) - i2) << 2);
            }
        }
        return new BigInteger(1, bArr);
    }

    public static void zero(int i, int[] iArr) {
        for (int i2 = 0; i2 < i; i2++) {
            iArr[i2] = 0;
        }
    }

    public static void zero(int i, int[] iArr, int i2) {
        for (int i3 = 0; i3 < i; i3++) {
            iArr[i2 + i3] = 0;
        }
    }

    public static void zero64(int i, long[] jArr) {
        for (int i2 = 0; i2 < i; i2++) {
            jArr[i2] = 0;
        }
    }
}