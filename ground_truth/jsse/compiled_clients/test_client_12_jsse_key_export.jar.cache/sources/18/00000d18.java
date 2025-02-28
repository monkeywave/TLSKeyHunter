package org.bouncycastle.math.raw;

import java.math.BigInteger;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/raw/Nat128.class */
public abstract class Nat128 {

    /* renamed from: M */
    private static final long f791M = 4294967295L;

    public static int add(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0 + (iArr[0] & f791M) + (iArr2[0] & f791M);
        iArr3[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & f791M) + (iArr2[1] & f791M);
        iArr3[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & f791M) + (iArr2[2] & f791M);
        iArr3[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & f791M) + (iArr2[3] & f791M);
        iArr3[3] = (int) j4;
        return (int) (j4 >>> 32);
    }

    public static int addBothTo(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0 + (iArr[0] & f791M) + (iArr2[0] & f791M) + (iArr3[0] & f791M);
        iArr3[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & f791M) + (iArr2[1] & f791M) + (iArr3[1] & f791M);
        iArr3[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & f791M) + (iArr2[2] & f791M) + (iArr3[2] & f791M);
        iArr3[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & f791M) + (iArr2[3] & f791M) + (iArr3[3] & f791M);
        iArr3[3] = (int) j4;
        return (int) (j4 >>> 32);
    }

    public static int addTo(int[] iArr, int[] iArr2) {
        long j = 0 + (iArr[0] & f791M) + (iArr2[0] & f791M);
        iArr2[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & f791M) + (iArr2[1] & f791M);
        iArr2[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & f791M) + (iArr2[2] & f791M);
        iArr2[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & f791M) + (iArr2[3] & f791M);
        iArr2[3] = (int) j4;
        return (int) (j4 >>> 32);
    }

    public static int addTo(int[] iArr, int i, int[] iArr2, int i2, int i3) {
        long j = (i3 & f791M) + (iArr[i + 0] & f791M) + (iArr2[i2 + 0] & f791M);
        iArr2[i2 + 0] = (int) j;
        long j2 = (j >>> 32) + (iArr[i + 1] & f791M) + (iArr2[i2 + 1] & f791M);
        iArr2[i2 + 1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i + 2] & f791M) + (iArr2[i2 + 2] & f791M);
        iArr2[i2 + 2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[i + 3] & f791M) + (iArr2[i2 + 3] & f791M);
        iArr2[i2 + 3] = (int) j4;
        return (int) (j4 >>> 32);
    }

    public static int addToEachOther(int[] iArr, int i, int[] iArr2, int i2) {
        long j = 0 + (iArr[i + 0] & f791M) + (iArr2[i2 + 0] & f791M);
        iArr[i + 0] = (int) j;
        iArr2[i2 + 0] = (int) j;
        long j2 = (j >>> 32) + (iArr[i + 1] & f791M) + (iArr2[i2 + 1] & f791M);
        iArr[i + 1] = (int) j2;
        iArr2[i2 + 1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i + 2] & f791M) + (iArr2[i2 + 2] & f791M);
        iArr[i + 2] = (int) j3;
        iArr2[i2 + 2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[i + 3] & f791M) + (iArr2[i2 + 3] & f791M);
        iArr[i + 3] = (int) j4;
        iArr2[i2 + 3] = (int) j4;
        return (int) (j4 >>> 32);
    }

    public static void copy(int[] iArr, int[] iArr2) {
        iArr2[0] = iArr[0];
        iArr2[1] = iArr[1];
        iArr2[2] = iArr[2];
        iArr2[3] = iArr[3];
    }

    public static void copy(int[] iArr, int i, int[] iArr2, int i2) {
        iArr2[i2 + 0] = iArr[i + 0];
        iArr2[i2 + 1] = iArr[i + 1];
        iArr2[i2 + 2] = iArr[i + 2];
        iArr2[i2 + 3] = iArr[i + 3];
    }

    public static void copy64(long[] jArr, long[] jArr2) {
        jArr2[0] = jArr[0];
        jArr2[1] = jArr[1];
    }

    public static void copy64(long[] jArr, int i, long[] jArr2, int i2) {
        jArr2[i2 + 0] = jArr[i + 0];
        jArr2[i2 + 1] = jArr[i + 1];
    }

    public static int[] create() {
        return new int[4];
    }

    public static long[] create64() {
        return new long[2];
    }

    public static int[] createExt() {
        return new int[8];
    }

    public static long[] createExt64() {
        return new long[4];
    }

    public static boolean diff(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        boolean gte = gte(iArr, i, iArr2, i2);
        if (gte) {
            sub(iArr, i, iArr2, i2, iArr3, i3);
        } else {
            sub(iArr2, i2, iArr, i, iArr3, i3);
        }
        return gte;
    }

    /* renamed from: eq */
    public static boolean m18eq(int[] iArr, int[] iArr2) {
        for (int i = 3; i >= 0; i--) {
            if (iArr[i] != iArr2[i]) {
                return false;
            }
        }
        return true;
    }

    public static boolean eq64(long[] jArr, long[] jArr2) {
        for (int i = 1; i >= 0; i--) {
            if (jArr[i] != jArr2[i]) {
                return false;
            }
        }
        return true;
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > 128) {
            throw new IllegalArgumentException();
        }
        int[] create = create();
        for (int i = 0; i < 4; i++) {
            create[i] = bigInteger.intValue();
            bigInteger = bigInteger.shiftRight(32);
        }
        return create;
    }

    public static long[] fromBigInteger64(BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > 128) {
            throw new IllegalArgumentException();
        }
        long[] create64 = create64();
        for (int i = 0; i < 2; i++) {
            create64[i] = bigInteger.longValue();
            bigInteger = bigInteger.shiftRight(64);
        }
        return create64;
    }

    public static int getBit(int[] iArr, int i) {
        if (i == 0) {
            return iArr[0] & 1;
        }
        int i2 = i >> 5;
        if (i2 < 0 || i2 >= 4) {
            return 0;
        }
        return (iArr[i2] >>> (i & 31)) & 1;
    }

    public static boolean gte(int[] iArr, int[] iArr2) {
        for (int i = 3; i >= 0; i--) {
            int i2 = iArr[i] ^ Integer.MIN_VALUE;
            int i3 = iArr2[i] ^ Integer.MIN_VALUE;
            if (i2 < i3) {
                return false;
            }
            if (i2 > i3) {
                return true;
            }
        }
        return true;
    }

    public static boolean gte(int[] iArr, int i, int[] iArr2, int i2) {
        for (int i3 = 3; i3 >= 0; i3--) {
            int i4 = iArr[i + i3] ^ Integer.MIN_VALUE;
            int i5 = iArr2[i2 + i3] ^ Integer.MIN_VALUE;
            if (i4 < i5) {
                return false;
            }
            if (i4 > i5) {
                return true;
            }
        }
        return true;
    }

    public static boolean isOne(int[] iArr) {
        if (iArr[0] != 1) {
            return false;
        }
        for (int i = 1; i < 4; i++) {
            if (iArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isOne64(long[] jArr) {
        if (jArr[0] != 1) {
            return false;
        }
        for (int i = 1; i < 2; i++) {
            if (jArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int[] iArr) {
        for (int i = 0; i < 4; i++) {
            if (iArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero64(long[] jArr) {
        for (int i = 0; i < 2; i++) {
            if (jArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = iArr2[0] & f791M;
        long j2 = iArr2[1] & f791M;
        long j3 = iArr2[2] & f791M;
        long j4 = iArr2[3] & f791M;
        long j5 = iArr[0] & f791M;
        long j6 = 0 + (j5 * j);
        iArr3[0] = (int) j6;
        long j7 = (j6 >>> 32) + (j5 * j2);
        iArr3[1] = (int) j7;
        long j8 = (j7 >>> 32) + (j5 * j3);
        iArr3[2] = (int) j8;
        long j9 = (j8 >>> 32) + (j5 * j4);
        iArr3[3] = (int) j9;
        iArr3[4] = (int) (j9 >>> 32);
        for (int i = 1; i < 4; i++) {
            long j10 = iArr[i] & f791M;
            long j11 = 0 + (j10 * j) + (iArr3[i + 0] & f791M);
            iArr3[i + 0] = (int) j11;
            long j12 = (j11 >>> 32) + (j10 * j2) + (iArr3[i + 1] & f791M);
            iArr3[i + 1] = (int) j12;
            long j13 = (j12 >>> 32) + (j10 * j3) + (iArr3[i + 2] & f791M);
            iArr3[i + 2] = (int) j13;
            long j14 = (j13 >>> 32) + (j10 * j4) + (iArr3[i + 3] & f791M);
            iArr3[i + 3] = (int) j14;
            iArr3[i + 4] = (int) (j14 >>> 32);
        }
    }

    public static void mul(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = iArr2[i2 + 0] & f791M;
        long j2 = iArr2[i2 + 1] & f791M;
        long j3 = iArr2[i2 + 2] & f791M;
        long j4 = iArr2[i2 + 3] & f791M;
        long j5 = iArr[i + 0] & f791M;
        long j6 = 0 + (j5 * j);
        iArr3[i3 + 0] = (int) j6;
        long j7 = (j6 >>> 32) + (j5 * j2);
        iArr3[i3 + 1] = (int) j7;
        long j8 = (j7 >>> 32) + (j5 * j3);
        iArr3[i3 + 2] = (int) j8;
        long j9 = (j8 >>> 32) + (j5 * j4);
        iArr3[i3 + 3] = (int) j9;
        iArr3[i3 + 4] = (int) (j9 >>> 32);
        for (int i4 = 1; i4 < 4; i4++) {
            i3++;
            long j10 = iArr[i + i4] & f791M;
            long j11 = 0 + (j10 * j) + (iArr3[i3 + 0] & f791M);
            iArr3[i3 + 0] = (int) j11;
            long j12 = (j11 >>> 32) + (j10 * j2) + (iArr3[i3 + 1] & f791M);
            iArr3[i3 + 1] = (int) j12;
            long j13 = (j12 >>> 32) + (j10 * j3) + (iArr3[i3 + 2] & f791M);
            iArr3[i3 + 2] = (int) j13;
            long j14 = (j13 >>> 32) + (j10 * j4) + (iArr3[i3 + 3] & f791M);
            iArr3[i3 + 3] = (int) j14;
            iArr3[i3 + 4] = (int) (j14 >>> 32);
        }
    }

    public static int mulAddTo(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = iArr2[0] & f791M;
        long j2 = iArr2[1] & f791M;
        long j3 = iArr2[2] & f791M;
        long j4 = iArr2[3] & f791M;
        long j5 = 0;
        for (int i = 0; i < 4; i++) {
            long j6 = iArr[i] & f791M;
            long j7 = 0 + (j6 * j) + (iArr3[i + 0] & f791M);
            iArr3[i + 0] = (int) j7;
            long j8 = (j7 >>> 32) + (j6 * j2) + (iArr3[i + 1] & f791M);
            iArr3[i + 1] = (int) j8;
            long j9 = (j8 >>> 32) + (j6 * j3) + (iArr3[i + 2] & f791M);
            iArr3[i + 2] = (int) j9;
            long j10 = (j9 >>> 32) + (j6 * j4) + (iArr3[i + 3] & f791M);
            iArr3[i + 3] = (int) j10;
            long j11 = j5 + (j10 >>> 32) + (iArr3[i + 4] & f791M);
            iArr3[i + 4] = (int) j11;
            j5 = j11 >>> 32;
        }
        return (int) j5;
    }

    public static int mulAddTo(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = iArr2[i2 + 0] & f791M;
        long j2 = iArr2[i2 + 1] & f791M;
        long j3 = iArr2[i2 + 2] & f791M;
        long j4 = iArr2[i2 + 3] & f791M;
        long j5 = 0;
        for (int i4 = 0; i4 < 4; i4++) {
            long j6 = iArr[i + i4] & f791M;
            long j7 = 0 + (j6 * j) + (iArr3[i3 + 0] & f791M);
            iArr3[i3 + 0] = (int) j7;
            long j8 = (j7 >>> 32) + (j6 * j2) + (iArr3[i3 + 1] & f791M);
            iArr3[i3 + 1] = (int) j8;
            long j9 = (j8 >>> 32) + (j6 * j3) + (iArr3[i3 + 2] & f791M);
            iArr3[i3 + 2] = (int) j9;
            long j10 = (j9 >>> 32) + (j6 * j4) + (iArr3[i3 + 3] & f791M);
            iArr3[i3 + 3] = (int) j10;
            long j11 = j5 + (j10 >>> 32) + (iArr3[i3 + 4] & f791M);
            iArr3[i3 + 4] = (int) j11;
            j5 = j11 >>> 32;
            i3++;
        }
        return (int) j5;
    }

    public static long mul33Add(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = i & f791M;
        long j2 = iArr[i2 + 0] & f791M;
        long j3 = 0 + (j * j2) + (iArr2[i3 + 0] & f791M);
        iArr3[i4 + 0] = (int) j3;
        long j4 = j3 >>> 32;
        long j5 = iArr[i2 + 1] & f791M;
        long j6 = j4 + (j * j5) + j2 + (iArr2[i3 + 1] & f791M);
        iArr3[i4 + 1] = (int) j6;
        long j7 = j6 >>> 32;
        long j8 = iArr[i2 + 2] & f791M;
        long j9 = j7 + (j * j8) + j5 + (iArr2[i3 + 2] & f791M);
        iArr3[i4 + 2] = (int) j9;
        long j10 = j9 >>> 32;
        long j11 = iArr[i2 + 3] & f791M;
        long j12 = j10 + (j * j11) + j8 + (iArr2[i3 + 3] & f791M);
        iArr3[i4 + 3] = (int) j12;
        return (j12 >>> 32) + j11;
    }

    public static int mulWordAddExt(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = i & f791M;
        long j2 = 0 + (j * (iArr[i2 + 0] & f791M)) + (iArr2[i3 + 0] & f791M);
        iArr2[i3 + 0] = (int) j2;
        long j3 = (j2 >>> 32) + (j * (iArr[i2 + 1] & f791M)) + (iArr2[i3 + 1] & f791M);
        iArr2[i3 + 1] = (int) j3;
        long j4 = (j3 >>> 32) + (j * (iArr[i2 + 2] & f791M)) + (iArr2[i3 + 2] & f791M);
        iArr2[i3 + 2] = (int) j4;
        long j5 = (j4 >>> 32) + (j * (iArr[i2 + 3] & f791M)) + (iArr2[i3 + 3] & f791M);
        iArr2[i3 + 3] = (int) j5;
        return (int) (j5 >>> 32);
    }

    public static int mul33DWordAdd(int i, long j, int[] iArr, int i2) {
        long j2 = i & f791M;
        long j3 = j & f791M;
        long j4 = 0 + (j2 * j3) + (iArr[i2 + 0] & f791M);
        iArr[i2 + 0] = (int) j4;
        long j5 = j4 >>> 32;
        long j6 = j >>> 32;
        long j7 = j5 + (j2 * j6) + j3 + (iArr[i2 + 1] & f791M);
        iArr[i2 + 1] = (int) j7;
        long j8 = (j7 >>> 32) + j6 + (iArr[i2 + 2] & f791M);
        iArr[i2 + 2] = (int) j8;
        long j9 = (j8 >>> 32) + (iArr[i2 + 3] & f791M);
        iArr[i2 + 3] = (int) j9;
        return (int) (j9 >>> 32);
    }

    public static int mul33WordAdd(int i, int i2, int[] iArr, int i3) {
        long j = i & f791M;
        long j2 = i2 & f791M;
        long j3 = 0 + (j2 * j) + (iArr[i3 + 0] & f791M);
        iArr[i3 + 0] = (int) j3;
        long j4 = (j3 >>> 32) + j2 + (iArr[i3 + 1] & f791M);
        iArr[i3 + 1] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[i3 + 2] & f791M);
        iArr[i3 + 2] = (int) j5;
        if ((j5 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, iArr, i3, 3);
    }

    public static int mulWordDwordAdd(int i, long j, int[] iArr, int i2) {
        long j2 = i & f791M;
        long j3 = 0 + (j2 * (j & f791M)) + (iArr[i2 + 0] & f791M);
        iArr[i2 + 0] = (int) j3;
        long j4 = (j3 >>> 32) + (j2 * (j >>> 32)) + (iArr[i2 + 1] & f791M);
        iArr[i2 + 1] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[i2 + 2] & f791M);
        iArr[i2 + 2] = (int) j5;
        if ((j5 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, iArr, i2, 3);
    }

    public static int mulWordsAdd(int i, int i2, int[] iArr, int i3) {
        long j = 0 + ((i2 & f791M) * (i & f791M)) + (iArr[i3 + 0] & f791M);
        iArr[i3 + 0] = (int) j;
        long j2 = (j >>> 32) + (iArr[i3 + 1] & f791M);
        iArr[i3 + 1] = (int) j2;
        if ((j2 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(4, iArr, i3, 2);
    }

    public static int mulWord(int i, int[] iArr, int[] iArr2, int i2) {
        long j = 0;
        long j2 = i & f791M;
        int i3 = 0;
        do {
            long j3 = j + (j2 * (iArr[i3] & f791M));
            iArr2[i2 + i3] = (int) j3;
            j = j3 >>> 32;
            i3++;
        } while (i3 < 4);
        return (int) j;
    }

    public static void square(int[] iArr, int[] iArr2) {
        long j = iArr[0] & f791M;
        int i = 0;
        int i2 = 3;
        int i3 = 8;
        do {
            int i4 = i2;
            i2--;
            long j2 = iArr[i4] & f791M;
            long j3 = j2 * j2;
            int i5 = i3 - 1;
            iArr2[i5] = (i << 31) | ((int) (j3 >>> 33));
            i3 = i5 - 1;
            iArr2[i3] = (int) (j3 >>> 1);
            i = (int) j3;
        } while (i2 > 0);
        long j4 = j * j;
        long j5 = ((i << 31) & f791M) | (j4 >>> 33);
        iArr2[0] = (int) j4;
        int i6 = ((int) (j4 >>> 32)) & 1;
        long j6 = iArr[1] & f791M;
        long j7 = iArr2[2] & f791M;
        long j8 = j5 + (j6 * j);
        int i7 = (int) j8;
        iArr2[1] = (i7 << 1) | i6;
        int i8 = i7 >>> 31;
        long j9 = j7 + (j8 >>> 32);
        long j10 = iArr[2] & f791M;
        long j11 = iArr2[3] & f791M;
        long j12 = iArr2[4] & f791M;
        long j13 = j9 + (j10 * j);
        int i9 = (int) j13;
        iArr2[2] = (i9 << 1) | i8;
        int i10 = i9 >>> 31;
        long j14 = j11 + (j13 >>> 32) + (j10 * j6);
        long j15 = j12 + (j14 >>> 32);
        long j16 = j14 & f791M;
        long j17 = iArr[3] & f791M;
        long j18 = (iArr2[5] & f791M) + (j15 >>> 32);
        long j19 = j15 & f791M;
        long j20 = (iArr2[6] & f791M) + (j18 >>> 32);
        long j21 = j18 & f791M;
        long j22 = j16 + (j17 * j);
        int i11 = (int) j22;
        iArr2[3] = (i11 << 1) | i10;
        int i12 = i11 >>> 31;
        long j23 = j19 + (j22 >>> 32) + (j17 * j6);
        long j24 = j21 + (j23 >>> 32) + (j17 * j10);
        long j25 = j20 + (j24 >>> 32);
        long j26 = j24 & f791M;
        int i13 = (int) j23;
        iArr2[4] = (i13 << 1) | i12;
        int i14 = i13 >>> 31;
        int i15 = (int) j26;
        iArr2[5] = (i15 << 1) | i14;
        int i16 = i15 >>> 31;
        int i17 = (int) j25;
        iArr2[6] = (i17 << 1) | i16;
        iArr2[7] = ((iArr2[7] + ((int) (j25 >>> 32))) << 1) | (i17 >>> 31);
    }

    public static void square(int[] iArr, int i, int[] iArr2, int i2) {
        long j = iArr[i + 0] & f791M;
        int i3 = 0;
        int i4 = 3;
        int i5 = 8;
        do {
            int i6 = i4;
            i4--;
            long j2 = iArr[i + i6] & f791M;
            long j3 = j2 * j2;
            int i7 = i5 - 1;
            iArr2[i2 + i7] = (i3 << 31) | ((int) (j3 >>> 33));
            i5 = i7 - 1;
            iArr2[i2 + i5] = (int) (j3 >>> 1);
            i3 = (int) j3;
        } while (i4 > 0);
        long j4 = j * j;
        long j5 = ((i3 << 31) & f791M) | (j4 >>> 33);
        iArr2[i2 + 0] = (int) j4;
        int i8 = ((int) (j4 >>> 32)) & 1;
        long j6 = iArr[i + 1] & f791M;
        long j7 = iArr2[i2 + 2] & f791M;
        long j8 = j5 + (j6 * j);
        int i9 = (int) j8;
        iArr2[i2 + 1] = (i9 << 1) | i8;
        int i10 = i9 >>> 31;
        long j9 = j7 + (j8 >>> 32);
        long j10 = iArr[i + 2] & f791M;
        long j11 = iArr2[i2 + 3] & f791M;
        long j12 = iArr2[i2 + 4] & f791M;
        long j13 = j9 + (j10 * j);
        int i11 = (int) j13;
        iArr2[i2 + 2] = (i11 << 1) | i10;
        int i12 = i11 >>> 31;
        long j14 = j11 + (j13 >>> 32) + (j10 * j6);
        long j15 = j12 + (j14 >>> 32);
        long j16 = j14 & f791M;
        long j17 = iArr[i + 3] & f791M;
        long j18 = (iArr2[i2 + 5] & f791M) + (j15 >>> 32);
        long j19 = j15 & f791M;
        long j20 = (iArr2[i2 + 6] & f791M) + (j18 >>> 32);
        long j21 = j18 & f791M;
        long j22 = j16 + (j17 * j);
        int i13 = (int) j22;
        iArr2[i2 + 3] = (i13 << 1) | i12;
        int i14 = i13 >>> 31;
        long j23 = j19 + (j22 >>> 32) + (j17 * j6);
        long j24 = j21 + (j23 >>> 32) + (j17 * j10);
        long j25 = j20 + (j24 >>> 32);
        int i15 = (int) j23;
        iArr2[i2 + 4] = (i15 << 1) | i14;
        int i16 = i15 >>> 31;
        int i17 = (int) j24;
        iArr2[i2 + 5] = (i17 << 1) | i16;
        int i18 = i17 >>> 31;
        int i19 = (int) j25;
        iArr2[i2 + 6] = (i19 << 1) | i18;
        iArr2[i2 + 7] = ((iArr2[i2 + 7] + ((int) (j25 >>> 32))) << 1) | (i19 >>> 31);
    }

    public static int sub(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0 + ((iArr[0] & f791M) - (iArr2[0] & f791M));
        iArr3[0] = (int) j;
        long j2 = (j >> 32) + ((iArr[1] & f791M) - (iArr2[1] & f791M));
        iArr3[1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[2] & f791M) - (iArr2[2] & f791M));
        iArr3[2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr[3] & f791M) - (iArr2[3] & f791M));
        iArr3[3] = (int) j4;
        return (int) (j4 >> 32);
    }

    public static int sub(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = 0 + ((iArr[i + 0] & f791M) - (iArr2[i2 + 0] & f791M));
        iArr3[i3 + 0] = (int) j;
        long j2 = (j >> 32) + ((iArr[i + 1] & f791M) - (iArr2[i2 + 1] & f791M));
        iArr3[i3 + 1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[i + 2] & f791M) - (iArr2[i2 + 2] & f791M));
        iArr3[i3 + 2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr[i + 3] & f791M) - (iArr2[i2 + 3] & f791M));
        iArr3[i3 + 3] = (int) j4;
        return (int) (j4 >> 32);
    }

    public static int subBothFrom(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = 0 + (((iArr3[0] & f791M) - (iArr[0] & f791M)) - (iArr2[0] & f791M));
        iArr3[0] = (int) j;
        long j2 = (j >> 32) + (((iArr3[1] & f791M) - (iArr[1] & f791M)) - (iArr2[1] & f791M));
        iArr3[1] = (int) j2;
        long j3 = (j2 >> 32) + (((iArr3[2] & f791M) - (iArr[2] & f791M)) - (iArr2[2] & f791M));
        iArr3[2] = (int) j3;
        long j4 = (j3 >> 32) + (((iArr3[3] & f791M) - (iArr[3] & f791M)) - (iArr2[3] & f791M));
        iArr3[3] = (int) j4;
        return (int) (j4 >> 32);
    }

    public static int subFrom(int[] iArr, int[] iArr2) {
        long j = 0 + ((iArr2[0] & f791M) - (iArr[0] & f791M));
        iArr2[0] = (int) j;
        long j2 = (j >> 32) + ((iArr2[1] & f791M) - (iArr[1] & f791M));
        iArr2[1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr2[2] & f791M) - (iArr[2] & f791M));
        iArr2[2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr2[3] & f791M) - (iArr[3] & f791M));
        iArr2[3] = (int) j4;
        return (int) (j4 >> 32);
    }

    public static int subFrom(int[] iArr, int i, int[] iArr2, int i2) {
        long j = 0 + ((iArr2[i2 + 0] & f791M) - (iArr[i + 0] & f791M));
        iArr2[i2 + 0] = (int) j;
        long j2 = (j >> 32) + ((iArr2[i2 + 1] & f791M) - (iArr[i + 1] & f791M));
        iArr2[i2 + 1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr2[i2 + 2] & f791M) - (iArr[i + 2] & f791M));
        iArr2[i2 + 2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr2[i2 + 3] & f791M) - (iArr[i + 3] & f791M));
        iArr2[i2 + 3] = (int) j4;
        return (int) (j4 >> 32);
    }

    public static BigInteger toBigInteger(int[] iArr) {
        byte[] bArr = new byte[16];
        for (int i = 0; i < 4; i++) {
            int i2 = iArr[i];
            if (i2 != 0) {
                Pack.intToBigEndian(i2, bArr, (3 - i) << 2);
            }
        }
        return new BigInteger(1, bArr);
    }

    public static BigInteger toBigInteger64(long[] jArr) {
        byte[] bArr = new byte[16];
        for (int i = 0; i < 2; i++) {
            long j = jArr[i];
            if (j != 0) {
                Pack.longToBigEndian(j, bArr, (1 - i) << 3);
            }
        }
        return new BigInteger(1, bArr);
    }

    public static void zero(int[] iArr) {
        iArr[0] = 0;
        iArr[1] = 0;
        iArr[2] = 0;
        iArr[3] = 0;
    }
}