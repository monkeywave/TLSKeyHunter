package org.bouncycastle.math.raw;

import java.math.BigInteger;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public abstract class Nat256 {

    /* renamed from: M */
    private static final long f1146M = 4294967295L;

    public static int add(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = (iArr[i] & 4294967295L) + (iArr2[i2] & 4294967295L);
        iArr3[i3] = (int) j;
        long j2 = (j >>> 32) + (iArr[i + 1] & 4294967295L) + (iArr2[i2 + 1] & 4294967295L);
        iArr3[i3 + 1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[i + 2] & 4294967295L) + (iArr2[i2 + 2] & 4294967295L);
        iArr3[i3 + 2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[i + 3] & 4294967295L) + (iArr2[i2 + 3] & 4294967295L);
        iArr3[i3 + 3] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[i + 4] & 4294967295L) + (iArr2[i2 + 4] & 4294967295L);
        iArr3[i3 + 4] = (int) j5;
        long j6 = (j5 >>> 32) + (iArr[i + 5] & 4294967295L) + (iArr2[i2 + 5] & 4294967295L);
        iArr3[i3 + 5] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[i + 6] & 4294967295L) + (iArr2[i2 + 6] & 4294967295L);
        iArr3[i3 + 6] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[i + 7] & 4294967295L) + (iArr2[i2 + 7] & 4294967295L);
        iArr3[i3 + 7] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int add(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = (iArr[0] & 4294967295L) + (iArr2[0] & 4294967295L);
        iArr3[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & 4294967295L) + (iArr2[1] & 4294967295L);
        iArr3[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & 4294967295L) + (iArr2[2] & 4294967295L);
        iArr3[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & 4294967295L) + (iArr2[3] & 4294967295L);
        iArr3[3] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[4] & 4294967295L) + (iArr2[4] & 4294967295L);
        iArr3[4] = (int) j5;
        long j6 = (j5 >>> 32) + (iArr[5] & 4294967295L) + (iArr2[5] & 4294967295L);
        iArr3[5] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[6] & 4294967295L) + (iArr2[6] & 4294967295L);
        iArr3[6] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[7] & 4294967295L) + (iArr2[7] & 4294967295L);
        iArr3[7] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addBothTo(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = (iArr[i] & 4294967295L) + (iArr2[i2] & 4294967295L) + (iArr3[i3] & 4294967295L);
        iArr3[i3] = (int) j;
        int i4 = i3 + 1;
        long j2 = (j >>> 32) + (iArr[i + 1] & 4294967295L) + (iArr2[i2 + 1] & 4294967295L) + (iArr3[i4] & 4294967295L);
        iArr3[i4] = (int) j2;
        int i5 = i3 + 2;
        long j3 = (j2 >>> 32) + (iArr[i + 2] & 4294967295L) + (iArr2[i2 + 2] & 4294967295L) + (iArr3[i5] & 4294967295L);
        iArr3[i5] = (int) j3;
        int i6 = i3 + 3;
        long j4 = (j3 >>> 32) + (iArr[i + 3] & 4294967295L) + (iArr2[i2 + 3] & 4294967295L) + (iArr3[i6] & 4294967295L);
        iArr3[i6] = (int) j4;
        int i7 = i3 + 4;
        long j5 = (j4 >>> 32) + (iArr[i + 4] & 4294967295L) + (iArr2[i2 + 4] & 4294967295L) + (iArr3[i7] & 4294967295L);
        iArr3[i7] = (int) j5;
        int i8 = i3 + 5;
        long j6 = (j5 >>> 32) + (iArr[i + 5] & 4294967295L) + (iArr2[i2 + 5] & 4294967295L) + (iArr3[i8] & 4294967295L);
        iArr3[i8] = (int) j6;
        int i9 = i3 + 6;
        long j7 = (j6 >>> 32) + (iArr[i + 6] & 4294967295L) + (iArr2[i2 + 6] & 4294967295L) + (iArr3[i9] & 4294967295L);
        iArr3[i9] = (int) j7;
        int i10 = i3 + 7;
        long j8 = (j7 >>> 32) + (iArr[i + 7] & 4294967295L) + (iArr2[i2 + 7] & 4294967295L) + (iArr3[i10] & 4294967295L);
        iArr3[i10] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addBothTo(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = (iArr[0] & 4294967295L) + (iArr2[0] & 4294967295L) + (iArr3[0] & 4294967295L);
        iArr3[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & 4294967295L) + (iArr2[1] & 4294967295L) + (iArr3[1] & 4294967295L);
        iArr3[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & 4294967295L) + (iArr2[2] & 4294967295L) + (iArr3[2] & 4294967295L);
        iArr3[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & 4294967295L) + (iArr2[3] & 4294967295L) + (iArr3[3] & 4294967295L);
        iArr3[3] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[4] & 4294967295L) + (iArr2[4] & 4294967295L) + (iArr3[4] & 4294967295L);
        iArr3[4] = (int) j5;
        long j6 = (j5 >>> 32) + (iArr[5] & 4294967295L) + (iArr2[5] & 4294967295L) + (iArr3[5] & 4294967295L);
        iArr3[5] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[6] & 4294967295L) + (iArr2[6] & 4294967295L) + (iArr3[6] & 4294967295L);
        iArr3[6] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[7] & 4294967295L) + (iArr2[7] & 4294967295L) + (iArr3[7] & 4294967295L);
        iArr3[7] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addTo(int[] iArr, int i, int[] iArr2, int i2, int i3) {
        long j = (i3 & 4294967295L) + (iArr[i] & 4294967295L) + (iArr2[i2] & 4294967295L);
        iArr2[i2] = (int) j;
        int i4 = i2 + 1;
        long j2 = (j >>> 32) + (iArr[i + 1] & 4294967295L) + (iArr2[i4] & 4294967295L);
        iArr2[i4] = (int) j2;
        int i5 = i2 + 2;
        long j3 = (j2 >>> 32) + (iArr[i + 2] & 4294967295L) + (iArr2[i5] & 4294967295L);
        iArr2[i5] = (int) j3;
        int i6 = i2 + 3;
        long j4 = (j3 >>> 32) + (iArr[i + 3] & 4294967295L) + (iArr2[i6] & 4294967295L);
        iArr2[i6] = (int) j4;
        int i7 = i2 + 4;
        long j5 = (j4 >>> 32) + (iArr[i + 4] & 4294967295L) + (iArr2[i7] & 4294967295L);
        iArr2[i7] = (int) j5;
        int i8 = i2 + 5;
        long j6 = (j5 >>> 32) + (iArr[i + 5] & 4294967295L) + (iArr2[i8] & 4294967295L);
        iArr2[i8] = (int) j6;
        int i9 = i2 + 6;
        long j7 = (j6 >>> 32) + (iArr[i + 6] & 4294967295L) + (iArr2[i9] & 4294967295L);
        iArr2[i9] = (int) j7;
        int i10 = i2 + 7;
        long j8 = (j7 >>> 32) + (iArr[i + 7] & 4294967295L) + (4294967295L & iArr2[i10]);
        iArr2[i10] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addTo(int[] iArr, int[] iArr2) {
        long j = (iArr[0] & 4294967295L) + (iArr2[0] & 4294967295L);
        iArr2[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & 4294967295L) + (iArr2[1] & 4294967295L);
        iArr2[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & 4294967295L) + (iArr2[2] & 4294967295L);
        iArr2[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & 4294967295L) + (iArr2[3] & 4294967295L);
        iArr2[3] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[4] & 4294967295L) + (iArr2[4] & 4294967295L);
        iArr2[4] = (int) j5;
        long j6 = (j5 >>> 32) + (iArr[5] & 4294967295L) + (iArr2[5] & 4294967295L);
        iArr2[5] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[6] & 4294967295L) + (iArr2[6] & 4294967295L);
        iArr2[6] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[7] & 4294967295L) + (4294967295L & iArr2[7]);
        iArr2[7] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addTo(int[] iArr, int[] iArr2, int i) {
        long j = (i & 4294967295L) + (iArr[0] & 4294967295L) + (iArr2[0] & 4294967295L);
        iArr2[0] = (int) j;
        long j2 = (j >>> 32) + (iArr[1] & 4294967295L) + (iArr2[1] & 4294967295L);
        iArr2[1] = (int) j2;
        long j3 = (j2 >>> 32) + (iArr[2] & 4294967295L) + (iArr2[2] & 4294967295L);
        iArr2[2] = (int) j3;
        long j4 = (j3 >>> 32) + (iArr[3] & 4294967295L) + (iArr2[3] & 4294967295L);
        iArr2[3] = (int) j4;
        long j5 = (j4 >>> 32) + (iArr[4] & 4294967295L) + (iArr2[4] & 4294967295L);
        iArr2[4] = (int) j5;
        long j6 = (j5 >>> 32) + (iArr[5] & 4294967295L) + (iArr2[5] & 4294967295L);
        iArr2[5] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[6] & 4294967295L) + (iArr2[6] & 4294967295L);
        iArr2[6] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[7] & 4294967295L) + (4294967295L & iArr2[7]);
        iArr2[7] = (int) j8;
        return (int) (j8 >>> 32);
    }

    public static int addToEachOther(int[] iArr, int i, int[] iArr2, int i2) {
        long j = (iArr[i] & 4294967295L) + (iArr2[i2] & 4294967295L);
        int i3 = (int) j;
        iArr[i] = i3;
        iArr2[i2] = i3;
        int i4 = i + 1;
        int i5 = i2 + 1;
        long j2 = (j >>> 32) + (iArr[i4] & 4294967295L) + (iArr2[i5] & 4294967295L);
        int i6 = (int) j2;
        iArr[i4] = i6;
        iArr2[i5] = i6;
        int i7 = i + 2;
        int i8 = i2 + 2;
        long j3 = (j2 >>> 32) + (iArr[i7] & 4294967295L) + (iArr2[i8] & 4294967295L);
        int i9 = (int) j3;
        iArr[i7] = i9;
        iArr2[i8] = i9;
        int i10 = i + 3;
        int i11 = i2 + 3;
        long j4 = (j3 >>> 32) + (iArr[i10] & 4294967295L) + (iArr2[i11] & 4294967295L);
        int i12 = (int) j4;
        iArr[i10] = i12;
        iArr2[i11] = i12;
        int i13 = i + 4;
        int i14 = i2 + 4;
        long j5 = (j4 >>> 32) + (iArr[i13] & 4294967295L) + (iArr2[i14] & 4294967295L);
        int i15 = (int) j5;
        iArr[i13] = i15;
        iArr2[i14] = i15;
        int i16 = i + 5;
        int i17 = i2 + 5;
        long j6 = (j5 >>> 32) + (iArr[i16] & 4294967295L) + (iArr2[i17] & 4294967295L);
        int i18 = (int) j6;
        iArr[i16] = i18;
        iArr2[i17] = i18;
        int i19 = i + 6;
        int i20 = i2 + 6;
        long j7 = (j6 >>> 32) + (iArr[i19] & 4294967295L) + (iArr2[i20] & 4294967295L);
        int i21 = (int) j7;
        iArr[i19] = i21;
        iArr2[i20] = i21;
        int i22 = i + 7;
        int i23 = i2 + 7;
        long j8 = (j7 >>> 32) + (iArr[i22] & 4294967295L) + (4294967295L & iArr2[i23]);
        int i24 = (int) j8;
        iArr[i22] = i24;
        iArr2[i23] = i24;
        return (int) (j8 >>> 32);
    }

    public static void copy(int[] iArr, int i, int[] iArr2, int i2) {
        iArr2[i2] = iArr[i];
        iArr2[i2 + 1] = iArr[i + 1];
        iArr2[i2 + 2] = iArr[i + 2];
        iArr2[i2 + 3] = iArr[i + 3];
        iArr2[i2 + 4] = iArr[i + 4];
        iArr2[i2 + 5] = iArr[i + 5];
        iArr2[i2 + 6] = iArr[i + 6];
        iArr2[i2 + 7] = iArr[i + 7];
    }

    public static void copy(int[] iArr, int[] iArr2) {
        iArr2[0] = iArr[0];
        iArr2[1] = iArr[1];
        iArr2[2] = iArr[2];
        iArr2[3] = iArr[3];
        iArr2[4] = iArr[4];
        iArr2[5] = iArr[5];
        iArr2[6] = iArr[6];
        iArr2[7] = iArr[7];
    }

    public static void copy64(long[] jArr, int i, long[] jArr2, int i2) {
        jArr2[i2] = jArr[i];
        jArr2[i2 + 1] = jArr[i + 1];
        jArr2[i2 + 2] = jArr[i + 2];
        jArr2[i2 + 3] = jArr[i + 3];
    }

    public static void copy64(long[] jArr, long[] jArr2) {
        jArr2[0] = jArr[0];
        jArr2[1] = jArr[1];
        jArr2[2] = jArr[2];
        jArr2[3] = jArr[3];
    }

    public static int[] create() {
        return new int[8];
    }

    public static long[] create64() {
        return new long[4];
    }

    public static int[] createExt() {
        return new int[16];
    }

    public static long[] createExt64() {
        return new long[8];
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
    public static boolean m30eq(int[] iArr, int[] iArr2) {
        for (int i = 7; i >= 0; i--) {
            if (iArr[i] != iArr2[i]) {
                return false;
            }
        }
        return true;
    }

    public static boolean eq64(long[] jArr, long[] jArr2) {
        for (int i = 3; i >= 0; i--) {
            if (jArr[i] != jArr2[i]) {
                return false;
            }
        }
        return true;
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > 256) {
            throw new IllegalArgumentException();
        }
        int[] create = create();
        for (int i = 0; i < 8; i++) {
            create[i] = bigInteger.intValue();
            bigInteger = bigInteger.shiftRight(32);
        }
        return create;
    }

    public static long[] fromBigInteger64(BigInteger bigInteger) {
        if (bigInteger.signum() < 0 || bigInteger.bitLength() > 256) {
            throw new IllegalArgumentException();
        }
        long[] create64 = create64();
        for (int i = 0; i < 4; i++) {
            create64[i] = bigInteger.longValue();
            bigInteger = bigInteger.shiftRight(64);
        }
        return create64;
    }

    public static int getBit(int[] iArr, int i) {
        int i2;
        if (i == 0) {
            i2 = iArr[0];
        } else if ((i & 255) != i) {
            return 0;
        } else {
            i2 = iArr[i >>> 5] >>> (i & 31);
        }
        return i2 & 1;
    }

    public static boolean gte(int[] iArr, int i, int[] iArr2, int i2) {
        for (int i3 = 7; i3 >= 0; i3--) {
            int i4 = iArr[i + i3] ^ Integer.MIN_VALUE;
            int i5 = Integer.MIN_VALUE ^ iArr2[i2 + i3];
            if (i4 < i5) {
                return false;
            }
            if (i4 > i5) {
                return true;
            }
        }
        return true;
    }

    public static boolean gte(int[] iArr, int[] iArr2) {
        for (int i = 7; i >= 0; i--) {
            int i2 = iArr[i] ^ Integer.MIN_VALUE;
            int i3 = Integer.MIN_VALUE ^ iArr2[i];
            if (i2 < i3) {
                return false;
            }
            if (i2 > i3) {
                return true;
            }
        }
        return true;
    }

    public static boolean isOne(int[] iArr) {
        if (iArr[0] != 1) {
            return false;
        }
        for (int i = 1; i < 8; i++) {
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
        for (int i = 1; i < 4; i++) {
            if (jArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero(int[] iArr) {
        for (int i = 0; i < 8; i++) {
            if (iArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static boolean isZero64(long[] jArr) {
        for (int i = 0; i < 4; i++) {
            if (jArr[i] != 0) {
                return false;
            }
        }
        return true;
    }

    public static void mul(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        long j = iArr2[i2] & 4294967295L;
        long j2 = iArr2[i2 + 1] & 4294967295L;
        long j3 = iArr2[i2 + 2] & 4294967295L;
        long j4 = iArr2[i2 + 3] & 4294967295L;
        long j5 = iArr2[i2 + 4] & 4294967295L;
        long j6 = iArr2[i2 + 5] & 4294967295L;
        long j7 = iArr2[i2 + 6] & 4294967295L;
        long j8 = iArr[i] & 4294967295L;
        long j9 = j8 * j;
        iArr3[i3] = (int) j9;
        long j10 = (j9 >>> 32) + (j8 * j2);
        iArr3[i3 + 1] = (int) j10;
        long j11 = (j10 >>> 32) + (j8 * j3);
        iArr3[i3 + 2] = (int) j11;
        long j12 = (j11 >>> 32) + (j8 * j4);
        iArr3[i3 + 3] = (int) j12;
        long j13 = (j12 >>> 32) + (j8 * j5);
        iArr3[i3 + 4] = (int) j13;
        long j14 = (j13 >>> 32) + (j8 * j6);
        iArr3[i3 + 5] = (int) j14;
        long j15 = (j14 >>> 32) + (j8 * j7);
        iArr3[i3 + 6] = (int) j15;
        long j16 = iArr2[i2 + 7] & 4294967295L;
        long j17 = (j15 >>> 32) + (j8 * j16);
        iArr3[i3 + 7] = (int) j17;
        iArr3[i3 + 8] = (int) (j17 >>> 32);
        int i11 = 1;
        int i12 = i3;
        while (i11 < 8) {
            int i13 = i12 + 1;
            long j18 = iArr[i + i11] & 4294967295L;
            long j19 = j16;
            int i14 = i11;
            long j20 = (j18 * j) + (iArr3[i13] & 4294967295L);
            iArr3[i13] = (int) j20;
            long j21 = (j20 >>> 32) + (j18 * j2) + (iArr3[i4] & 4294967295L);
            iArr3[i12 + 2] = (int) j21;
            long j22 = j3;
            long j23 = (j21 >>> 32) + (j18 * j3) + (iArr3[i5] & 4294967295L);
            iArr3[i12 + 3] = (int) j23;
            int i15 = i12;
            long j24 = (j23 >>> 32) + (j18 * j4) + (iArr3[i6] & 4294967295L);
            iArr3[i12 + 4] = (int) j24;
            long j25 = (j24 >>> 32) + (j18 * j5) + (iArr3[i7] & 4294967295L);
            iArr3[i15 + 5] = (int) j25;
            long j26 = (j25 >>> 32) + (j18 * j6) + (iArr3[i8] & 4294967295L);
            iArr3[i15 + 6] = (int) j26;
            long j27 = (j26 >>> 32) + (j18 * j7) + (iArr3[i9] & 4294967295L);
            iArr3[i15 + 7] = (int) j27;
            long j28 = (j27 >>> 32) + (j18 * j19) + (iArr3[i10] & 4294967295L);
            iArr3[i15 + 8] = (int) j28;
            iArr3[i15 + 9] = (int) (j28 >>> 32);
            i11 = i14 + 1;
            i12 = i13;
            j3 = j22;
            j16 = j19;
        }
    }

    public static void mul(int[] iArr, int[] iArr2, int[] iArr3) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        long j = iArr2[0] & 4294967295L;
        long j2 = iArr2[1] & 4294967295L;
        long j3 = iArr2[2] & 4294967295L;
        long j4 = iArr2[3] & 4294967295L;
        long j5 = iArr2[4] & 4294967295L;
        long j6 = iArr2[5] & 4294967295L;
        long j7 = iArr2[6] & 4294967295L;
        long j8 = iArr2[7] & 4294967295L;
        long j9 = iArr[0] & 4294967295L;
        long j10 = j9 * j;
        iArr3[0] = (int) j10;
        long j11 = (j10 >>> 32) + (j9 * j2);
        iArr3[1] = (int) j11;
        long j12 = (j11 >>> 32) + (j9 * j3);
        iArr3[2] = (int) j12;
        long j13 = (j12 >>> 32) + (j9 * j4);
        iArr3[3] = (int) j13;
        long j14 = (j13 >>> 32) + (j9 * j5);
        iArr3[4] = (int) j14;
        long j15 = (j14 >>> 32) + (j9 * j6);
        iArr3[5] = (int) j15;
        long j16 = (j15 >>> 32) + (j9 * j7);
        iArr3[6] = (int) j16;
        long j17 = (j16 >>> 32) + (j9 * j8);
        iArr3[7] = (int) j17;
        iArr3[8] = (int) (j17 >>> 32);
        int i7 = 1;
        for (int i8 = 8; i7 < i8; i8 = 8) {
            long j18 = iArr[i7] & 4294967295L;
            long j19 = (j18 * j) + (iArr3[i7] & 4294967295L);
            iArr3[i7] = (int) j19;
            int i9 = i7 + 1;
            long j20 = (j19 >>> 32) + (j18 * j2) + (iArr3[i9] & 4294967295L);
            iArr3[i9] = (int) j20;
            long j21 = j2;
            long j22 = (j20 >>> 32) + (j18 * j3) + (iArr3[i] & 4294967295L);
            iArr3[i7 + 2] = (int) j22;
            long j23 = (j22 >>> 32) + (j18 * j4) + (iArr3[i2] & 4294967295L);
            iArr3[i7 + 3] = (int) j23;
            long j24 = (j23 >>> 32) + (j18 * j5) + (iArr3[i3] & 4294967295L);
            iArr3[i7 + 4] = (int) j24;
            long j25 = (j24 >>> 32) + (j18 * j6) + (iArr3[i4] & 4294967295L);
            iArr3[i7 + 5] = (int) j25;
            long j26 = (j25 >>> 32) + (j18 * j7) + (iArr3[i5] & 4294967295L);
            iArr3[i7 + 6] = (int) j26;
            long j27 = (j26 >>> 32) + (j18 * j8) + (iArr3[i6] & 4294967295L);
            iArr3[i7 + 7] = (int) j27;
            iArr3[i7 + 8] = (int) (j27 >>> 32);
            j4 = j4;
            j = j;
            i7 = i9;
            j2 = j21;
        }
    }

    public static void mul128(int[] iArr, int[] iArr2, int[] iArr3) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        long j = iArr[0] & 4294967295L;
        long j2 = iArr[1] & 4294967295L;
        long j3 = iArr[2] & 4294967295L;
        long j4 = iArr[3] & 4294967295L;
        long j5 = iArr[4] & 4294967295L;
        long j6 = iArr[5] & 4294967295L;
        long j7 = iArr[6] & 4294967295L;
        long j8 = iArr[7] & 4294967295L;
        long j9 = iArr2[0] & 4294967295L;
        long j10 = j9 * j;
        iArr3[0] = (int) j10;
        char c = ' ';
        long j11 = (j10 >>> 32) + (j9 * j2);
        iArr3[1] = (int) j11;
        long j12 = (j11 >>> 32) + (j9 * j3);
        iArr3[2] = (int) j12;
        long j13 = (j12 >>> 32) + (j9 * j4);
        iArr3[3] = (int) j13;
        long j14 = (j13 >>> 32) + (j9 * j5);
        iArr3[4] = (int) j14;
        long j15 = (j14 >>> 32) + (j9 * j6);
        iArr3[5] = (int) j15;
        long j16 = (j15 >>> 32) + (j9 * j7);
        iArr3[6] = (int) j16;
        long j17 = (j16 >>> 32) + (j9 * j8);
        iArr3[7] = (int) j17;
        iArr3[8] = (int) (j17 >>> 32);
        int i7 = 1;
        while (i7 < 4) {
            long j18 = iArr2[i7] & 4294967295L;
            long j19 = (j18 * j) + (iArr3[i7] & 4294967295L);
            long j20 = j;
            iArr3[i7] = (int) j19;
            int i8 = i7 + 1;
            long j21 = j2;
            long j22 = (j19 >>> c) + (j18 * j2) + (iArr3[i8] & 4294967295L);
            iArr3[i8] = (int) j22;
            long j23 = (j22 >>> 32) + (j18 * j3) + (iArr3[i] & 4294967295L);
            iArr3[i7 + 2] = (int) j23;
            long j24 = (j23 >>> 32) + (j18 * j4) + (iArr3[i2] & 4294967295L);
            iArr3[i7 + 3] = (int) j24;
            long j25 = (j24 >>> 32) + (j18 * j5) + (iArr3[i3] & 4294967295L);
            iArr3[i7 + 4] = (int) j25;
            long j26 = (j25 >>> 32) + (j18 * j6) + (iArr3[i4] & 4294967295L);
            iArr3[i7 + 5] = (int) j26;
            long j27 = (j26 >>> 32) + (j18 * j7) + (iArr3[i5] & 4294967295L);
            iArr3[i7 + 6] = (int) j27;
            c = ' ';
            long j28 = (j27 >>> 32) + (j18 * j8) + (iArr3[i6] & 4294967295L);
            iArr3[i7 + 7] = (int) j28;
            iArr3[i7 + 8] = (int) (j28 >>> 32);
            j = j20;
            i7 = i8;
            j2 = j21;
        }
    }

    public static long mul33Add(int i, int[] iArr, int i2, int[] iArr2, int i3, int[] iArr3, int i4) {
        long j = i & 4294967295L;
        long j2 = iArr[i2] & 4294967295L;
        long j3 = (j * j2) + (iArr2[i3] & 4294967295L);
        iArr3[i4] = (int) j3;
        long j4 = iArr[i2 + 1] & 4294967295L;
        long j5 = (j3 >>> 32) + (j * j4) + j2 + (iArr2[i3 + 1] & 4294967295L);
        iArr3[i4 + 1] = (int) j5;
        long j6 = j5 >>> 32;
        long j7 = iArr[i2 + 2] & 4294967295L;
        long j8 = j6 + (j * j7) + j4 + (iArr2[i3 + 2] & 4294967295L);
        iArr3[i4 + 2] = (int) j8;
        long j9 = iArr[i2 + 3] & 4294967295L;
        long j10 = (j8 >>> 32) + (j * j9) + j7 + (iArr2[i3 + 3] & 4294967295L);
        iArr3[i4 + 3] = (int) j10;
        long j11 = iArr[i2 + 4] & 4294967295L;
        long j12 = (j10 >>> 32) + (j * j11) + j9 + (iArr2[i3 + 4] & 4294967295L);
        iArr3[i4 + 4] = (int) j12;
        long j13 = iArr[i2 + 5] & 4294967295L;
        long j14 = (j12 >>> 32) + (j * j13) + j11 + (iArr2[i3 + 5] & 4294967295L);
        iArr3[i4 + 5] = (int) j14;
        long j15 = iArr[i2 + 6] & 4294967295L;
        long j16 = (j14 >>> 32) + (j * j15) + j13 + (iArr2[i3 + 6] & 4294967295L);
        iArr3[i4 + 6] = (int) j16;
        long j17 = iArr[i2 + 7] & 4294967295L;
        long j18 = (j16 >>> 32) + (j * j17) + j15 + (4294967295L & iArr2[i3 + 7]);
        iArr3[i4 + 7] = (int) j18;
        return (j18 >>> 32) + j17;
    }

    public static int mul33DWordAdd(int i, long j, int[] iArr, int i2) {
        long j2 = i & 4294967295L;
        long j3 = j & 4294967295L;
        long j4 = (j2 * j3) + (iArr[i2] & 4294967295L);
        iArr[i2] = (int) j4;
        long j5 = j >>> 32;
        long j6 = (j2 * j5) + j3;
        int i3 = i2 + 1;
        long j7 = (j4 >>> 32) + j6 + (iArr[i3] & 4294967295L);
        iArr[i3] = (int) j7;
        int i4 = i2 + 2;
        long j8 = (j7 >>> 32) + j5 + (iArr[i4] & 4294967295L);
        iArr[i4] = (int) j8;
        long j9 = j8 >>> 32;
        int i5 = i2 + 3;
        long j10 = j9 + (iArr[i5] & 4294967295L);
        iArr[i5] = (int) j10;
        if ((j10 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(8, iArr, i2, 4);
    }

    public static int mul33WordAdd(int i, int i2, int[] iArr, int i3) {
        long j = i2 & 4294967295L;
        long j2 = ((i & 4294967295L) * j) + (iArr[i3] & 4294967295L);
        iArr[i3] = (int) j2;
        int i4 = i3 + 1;
        long j3 = (j2 >>> 32) + j + (iArr[i4] & 4294967295L);
        iArr[i4] = (int) j3;
        long j4 = j3 >>> 32;
        int i5 = i3 + 2;
        long j5 = j4 + (iArr[i5] & 4294967295L);
        iArr[i5] = (int) j5;
        if ((j5 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(8, iArr, i3, 3);
    }

    public static int mulAddTo(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        long j = iArr2[i2] & 4294967295L;
        long j2 = iArr2[i2 + 1] & 4294967295L;
        long j3 = iArr2[i2 + 2] & 4294967295L;
        long j4 = iArr2[i2 + 3] & 4294967295L;
        long j5 = iArr2[i2 + 4] & 4294967295L;
        long j6 = iArr2[i2 + 5] & 4294967295L;
        long j7 = iArr2[i2 + 6] & 4294967295L;
        long j8 = iArr2[i2 + 7] & 4294967295L;
        int i11 = 0;
        long j9 = 0;
        int i12 = i3;
        while (i11 < 8) {
            int i13 = i11;
            long j10 = iArr[i + i11] & 4294967295L;
            long j11 = j;
            long j12 = (j10 * j) + (iArr3[i12] & 4294967295L);
            long j13 = j8;
            iArr3[i12] = (int) j12;
            int i14 = i12 + 1;
            long j14 = (j12 >>> 32) + (j10 * j2) + (iArr3[i14] & 4294967295L);
            iArr3[i14] = (int) j14;
            long j15 = (j14 >>> 32) + (j10 * j3) + (iArr3[i4] & 4294967295L);
            iArr3[i12 + 2] = (int) j15;
            long j16 = (j15 >>> 32) + (j10 * j4) + (iArr3[i5] & 4294967295L);
            iArr3[i12 + 3] = (int) j16;
            long j17 = (j16 >>> 32) + (j10 * j5) + (iArr3[i6] & 4294967295L);
            iArr3[i12 + 4] = (int) j17;
            long j18 = (j17 >>> 32) + (j10 * j6) + (iArr3[i7] & 4294967295L);
            iArr3[i12 + 5] = (int) j18;
            long j19 = (j18 >>> 32) + (j10 * j7) + (iArr3[i8] & 4294967295L);
            iArr3[i12 + 6] = (int) j19;
            long j20 = (j19 >>> 32) + (j10 * j13) + (iArr3[i9] & 4294967295L);
            iArr3[i12 + 7] = (int) j20;
            long j21 = (j20 >>> 32) + (iArr3[i10] & 4294967295L) + j9;
            iArr3[i12 + 8] = (int) j21;
            j9 = j21 >>> 32;
            i11 = i13 + 1;
            i12 = i14;
            j8 = j13;
            j = j11;
            j2 = j2;
        }
        return (int) j9;
    }

    public static int mulAddTo(int[] iArr, int[] iArr2, int[] iArr3) {
        int i;
        int i2;
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        long j = iArr2[0] & 4294967295L;
        long j2 = iArr2[1] & 4294967295L;
        long j3 = iArr2[2] & 4294967295L;
        long j4 = iArr2[3] & 4294967295L;
        long j5 = iArr2[4] & 4294967295L;
        long j6 = iArr2[5] & 4294967295L;
        long j7 = iArr2[6] & 4294967295L;
        long j8 = iArr2[7] & 4294967295L;
        long j9 = 0;
        int i8 = 0;
        while (i8 < 8) {
            long j10 = j8;
            long j11 = iArr[i8] & 4294967295L;
            long j12 = j6;
            long j13 = (iArr3[i8] & 4294967295L) + (j11 * j);
            iArr3[i8] = (int) j13;
            int i9 = i8 + 1;
            long j14 = j2;
            long j15 = (j13 >>> 32) + (j11 * j2) + (iArr3[i9] & 4294967295L);
            iArr3[i9] = (int) j15;
            long j16 = (j15 >>> 32) + (j11 * j3) + (iArr3[i] & 4294967295L);
            iArr3[i8 + 2] = (int) j16;
            long j17 = (j16 >>> 32) + (j11 * j4) + (iArr3[i2] & 4294967295L);
            iArr3[i8 + 3] = (int) j17;
            long j18 = (j17 >>> 32) + (j11 * j5) + (iArr3[i3] & 4294967295L);
            iArr3[i8 + 4] = (int) j18;
            long j19 = (j18 >>> 32) + (j11 * j12) + (iArr3[i4] & 4294967295L);
            iArr3[i8 + 5] = (int) j19;
            long j20 = (j19 >>> 32) + (j11 * j7) + (iArr3[i5] & 4294967295L);
            iArr3[i8 + 6] = (int) j20;
            long j21 = (j20 >>> 32) + (j11 * j10) + (iArr3[i6] & 4294967295L);
            iArr3[i8 + 7] = (int) j21;
            long j22 = (j21 >>> 32) + (iArr3[i7] & 4294967295L) + j9;
            iArr3[i8 + 8] = (int) j22;
            j9 = j22 >>> 32;
            i8 = i9;
            j8 = j10;
            j6 = j12;
            j2 = j14;
        }
        return (int) j9;
    }

    public static int mulByWord(int i, int[] iArr) {
        long j = i & 4294967295L;
        long j2 = (iArr[0] & 4294967295L) * j;
        iArr[0] = (int) j2;
        long j3 = (j2 >>> 32) + ((iArr[1] & 4294967295L) * j);
        iArr[1] = (int) j3;
        long j4 = (j3 >>> 32) + ((iArr[2] & 4294967295L) * j);
        iArr[2] = (int) j4;
        long j5 = (j4 >>> 32) + ((iArr[3] & 4294967295L) * j);
        iArr[3] = (int) j5;
        long j6 = (j5 >>> 32) + ((iArr[4] & 4294967295L) * j);
        iArr[4] = (int) j6;
        long j7 = (j6 >>> 32) + ((iArr[5] & 4294967295L) * j);
        iArr[5] = (int) j7;
        long j8 = (j7 >>> 32) + ((iArr[6] & 4294967295L) * j);
        iArr[6] = (int) j8;
        long j9 = (j8 >>> 32) + (j * (4294967295L & iArr[7]));
        iArr[7] = (int) j9;
        return (int) (j9 >>> 32);
    }

    public static int mulByWordAddTo(int i, int[] iArr, int[] iArr2) {
        long j = i & 4294967295L;
        long j2 = ((iArr2[0] & 4294967295L) * j) + (iArr[0] & 4294967295L);
        iArr2[0] = (int) j2;
        long j3 = (j2 >>> 32) + ((iArr2[1] & 4294967295L) * j) + (iArr[1] & 4294967295L);
        iArr2[1] = (int) j3;
        long j4 = (j3 >>> 32) + ((iArr2[2] & 4294967295L) * j) + (iArr[2] & 4294967295L);
        iArr2[2] = (int) j4;
        long j5 = (j4 >>> 32) + ((iArr2[3] & 4294967295L) * j) + (iArr[3] & 4294967295L);
        iArr2[3] = (int) j5;
        long j6 = (j5 >>> 32) + ((iArr2[4] & 4294967295L) * j) + (iArr[4] & 4294967295L);
        iArr2[4] = (int) j6;
        long j7 = (j6 >>> 32) + ((iArr2[5] & 4294967295L) * j) + (iArr[5] & 4294967295L);
        iArr2[5] = (int) j7;
        long j8 = (j7 >>> 32) + ((iArr2[6] & 4294967295L) * j) + (iArr[6] & 4294967295L);
        iArr2[6] = (int) j8;
        long j9 = (j8 >>> 32) + (j * (iArr2[7] & 4294967295L)) + (4294967295L & iArr[7]);
        iArr2[7] = (int) j9;
        return (int) (j9 >>> 32);
    }

    public static int mulWord(int i, int[] iArr, int[] iArr2, int i2) {
        long j = i & 4294967295L;
        long j2 = 0;
        int i3 = 0;
        do {
            long j3 = j2 + ((iArr[i3] & 4294967295L) * j);
            iArr2[i2 + i3] = (int) j3;
            j2 = j3 >>> 32;
            i3++;
        } while (i3 < 8);
        return (int) j2;
    }

    public static int mulWordAddTo(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        long j = i & 4294967295L;
        long j2 = ((iArr[i2] & 4294967295L) * j) + (iArr2[i3] & 4294967295L);
        iArr2[i3] = (int) j2;
        int i4 = i3 + 1;
        long j3 = (j2 >>> 32) + ((iArr[i2 + 1] & 4294967295L) * j) + (iArr2[i4] & 4294967295L);
        iArr2[i4] = (int) j3;
        int i5 = i3 + 2;
        long j4 = (j3 >>> 32) + ((iArr[i2 + 2] & 4294967295L) * j) + (iArr2[i5] & 4294967295L);
        iArr2[i5] = (int) j4;
        int i6 = i3 + 3;
        long j5 = (j4 >>> 32) + ((iArr[i2 + 3] & 4294967295L) * j) + (iArr2[i6] & 4294967295L);
        iArr2[i6] = (int) j5;
        int i7 = i3 + 4;
        long j6 = (j5 >>> 32) + ((iArr[i2 + 4] & 4294967295L) * j) + (iArr2[i7] & 4294967295L);
        iArr2[i7] = (int) j6;
        int i8 = i3 + 5;
        long j7 = (j6 >>> 32) + ((iArr[i2 + 5] & 4294967295L) * j) + (iArr2[i8] & 4294967295L);
        iArr2[i8] = (int) j7;
        int i9 = i3 + 6;
        long j8 = (j7 >>> 32) + ((iArr[i2 + 6] & 4294967295L) * j) + (iArr2[i9] & 4294967295L);
        iArr2[i9] = (int) j8;
        int i10 = i3 + 7;
        long j9 = (j8 >>> 32) + (j * (iArr[i2 + 7] & 4294967295L)) + (iArr2[i10] & 4294967295L);
        iArr2[i10] = (int) j9;
        return (int) (j9 >>> 32);
    }

    public static int mulWordDwordAdd(int i, long j, int[] iArr, int i2) {
        long j2 = i & 4294967295L;
        long j3 = ((j & 4294967295L) * j2) + (iArr[i2] & 4294967295L);
        iArr[i2] = (int) j3;
        long j4 = j2 * (j >>> 32);
        int i3 = i2 + 1;
        long j5 = (j3 >>> 32) + j4 + (iArr[i3] & 4294967295L);
        iArr[i3] = (int) j5;
        int i4 = i2 + 2;
        long j6 = (j5 >>> 32) + (iArr[i4] & 4294967295L);
        iArr[i4] = (int) j6;
        if ((j6 >>> 32) == 0) {
            return 0;
        }
        return Nat.incAt(8, iArr, i2, 3);
    }

    public static void square(int[] iArr, int i, int[] iArr2, int i2) {
        int i3;
        int i4;
        int i5;
        int i6;
        int i7;
        int i8;
        int i9;
        int i10;
        int i11;
        int i12;
        int i13;
        int i14;
        int i15;
        long j = iArr[i] & 4294967295L;
        int i16 = 0;
        int i17 = 16;
        int i18 = 7;
        while (true) {
            int i19 = i18 - 1;
            long j2 = iArr[i + i18] & 4294967295L;
            long j3 = j2 * j2;
            iArr2[i2 + (i17 - 1)] = (i16 << 31) | ((int) (j3 >>> 33));
            i17 -= 2;
            iArr2[i2 + i17] = (int) (j3 >>> 1);
            i16 = (int) j3;
            if (i19 <= 0) {
                long j4 = j * j;
                iArr2[i2] = (int) j4;
                long j5 = iArr[i + 1] & 4294967295L;
                long j6 = ((j4 >>> 33) | ((i16 << 31) & 4294967295L)) + (j5 * j);
                int i20 = (int) j6;
                iArr2[i2 + 1] = (i20 << 1) | (((int) (j4 >>> 32)) & 1);
                int i21 = i20 >>> 31;
                long j7 = (iArr2[i3] & 4294967295L) + (j6 >>> 32);
                long j8 = iArr[i + 2] & 4294967295L;
                long j9 = iArr2[i4] & 4294967295L;
                long j10 = j7 + (j8 * j);
                int i22 = (int) j10;
                iArr2[i2 + 2] = (i22 << 1) | i21;
                long j11 = j9 + (j10 >>> 32) + (j8 * j5);
                long j12 = (iArr2[i5] & 4294967295L) + (j11 >>> 32);
                long j13 = iArr[i + 3] & 4294967295L;
                long j14 = (iArr2[i6] & 4294967295L) + (j12 >>> 32);
                long j15 = j12 & 4294967295L;
                long j16 = (iArr2[i7] & 4294967295L) + (j14 >>> 32);
                long j17 = (j11 & 4294967295L) + (j13 * j);
                int i23 = (int) j17;
                iArr2[i2 + 3] = (i23 << 1) | (i22 >>> 31);
                long j18 = j15 + (j17 >>> 32) + (j13 * j5);
                long j19 = (j14 & 4294967295L) + (j18 >>> 32) + (j13 * j8);
                long j20 = j16 + (j19 >>> 32);
                long j21 = j19 & 4294967295L;
                long j22 = iArr[i + 4] & 4294967295L;
                long j23 = (iArr2[i8] & 4294967295L) + (j20 >>> 32);
                long j24 = (iArr2[i9] & 4294967295L) + (j23 >>> 32);
                long j25 = (j18 & 4294967295L) + (j22 * j);
                int i24 = (int) j25;
                iArr2[i2 + 4] = (i24 << 1) | (i23 >>> 31);
                int i25 = i24 >>> 31;
                long j26 = j21 + (j25 >>> 32) + (j22 * j5);
                long j27 = (j20 & 4294967295L) + (j26 >>> 32) + (j22 * j8);
                long j28 = (j23 & 4294967295L) + (j27 >>> 32) + (j22 * j13);
                long j29 = j24 + (j28 >>> 32);
                long j30 = j28 & 4294967295L;
                long j31 = iArr[i + 5] & 4294967295L;
                long j32 = (iArr2[i10] & 4294967295L) + (j29 >>> 32);
                long j33 = j29 & 4294967295L;
                long j34 = (iArr2[i11] & 4294967295L) + (j32 >>> 32);
                long j35 = (j26 & 4294967295L) + (j31 * j);
                int i26 = (int) j35;
                iArr2[i2 + 5] = (i26 << 1) | i25;
                int i27 = i26 >>> 31;
                long j36 = (j27 & 4294967295L) + (j35 >>> 32) + (j31 * j5);
                long j37 = j30 + (j36 >>> 32) + (j31 * j8);
                long j38 = j33 + (j37 >>> 32) + (j31 * j13);
                long j39 = (j32 & 4294967295L) + (j38 >>> 32) + (j31 * j22);
                long j40 = j34 + (j39 >>> 32);
                long j41 = j39 & 4294967295L;
                long j42 = iArr[i + 6] & 4294967295L;
                long j43 = (iArr2[i12] & 4294967295L) + (j40 >>> 32);
                long j44 = (j36 & 4294967295L) + (j42 * j);
                int i28 = (int) j44;
                iArr2[i2 + 6] = (i28 << 1) | i27;
                int i29 = i28 >>> 31;
                long j45 = (j37 & 4294967295L) + (j44 >>> 32) + (j42 * j5);
                long j46 = (j38 & 4294967295L) + (j45 >>> 32) + (j42 * j8);
                long j47 = j41 + (j46 >>> 32) + (j42 * j13);
                long j48 = j46 & 4294967295L;
                long j49 = (j40 & 4294967295L) + (j47 >>> 32) + (j42 * j22);
                long j50 = (j43 & 4294967295L) + (j49 >>> 32) + (j42 * j31);
                long j51 = (iArr2[i13] & 4294967295L) + (j43 >>> 32) + (j50 >>> 32);
                long j52 = j50 & 4294967295L;
                long j53 = iArr[i + 7] & 4294967295L;
                long j54 = (iArr2[i14] & 4294967295L) + (j51 >>> 32);
                long j55 = 4294967295L & j54;
                long j56 = (j45 & 4294967295L) + (j * j53);
                int i30 = (int) j56;
                iArr2[i2 + 7] = (i30 << 1) | i29;
                long j57 = j48 + (j56 >>> 32) + (j5 * j53);
                long j58 = (j47 & 4294967295L) + (j57 >>> 32) + (j53 * j8);
                long j59 = (j49 & 4294967295L) + (j58 >>> 32) + (j53 * j13);
                long j60 = j52 + (j59 >>> 32) + (j53 * j22);
                long j61 = (j51 & 4294967295L) + (j60 >>> 32) + (j53 * j31);
                long j62 = j55 + (j61 >>> 32) + (j53 * j42);
                long j63 = (iArr2[i15] & 4294967295L) + (j54 >>> 32) + (j62 >>> 32);
                int i31 = (int) j57;
                iArr2[i2 + 8] = (i30 >>> 31) | (i31 << 1);
                int i32 = i31 >>> 31;
                int i33 = (int) j58;
                iArr2[i2 + 9] = i32 | (i33 << 1);
                int i34 = i33 >>> 31;
                int i35 = (int) j59;
                iArr2[i2 + 10] = i34 | (i35 << 1);
                int i36 = i35 >>> 31;
                int i37 = (int) j60;
                iArr2[i2 + 11] = i36 | (i37 << 1);
                int i38 = i37 >>> 31;
                int i39 = (int) j61;
                iArr2[i2 + 12] = i38 | (i39 << 1);
                int i40 = i39 >>> 31;
                int i41 = (int) j62;
                iArr2[i2 + 13] = i40 | (i41 << 1);
                int i42 = i41 >>> 31;
                int i43 = (int) j63;
                iArr2[i2 + 14] = i42 | (i43 << 1);
                int i44 = i43 >>> 31;
                int i45 = i2 + 15;
                iArr2[i45] = i44 | ((iArr2[i45] + ((int) (j63 >>> 32))) << 1);
                return;
            }
            i18 = i19;
        }
    }

    public static void square(int[] iArr, int[] iArr2) {
        long j = iArr[0] & 4294967295L;
        int i = 16;
        int i2 = 0;
        int i3 = 7;
        while (true) {
            int i4 = i3 - 1;
            long j2 = iArr[i3] & 4294967295L;
            long j3 = j2 * j2;
            iArr2[i - 1] = (i2 << 31) | ((int) (j3 >>> 33));
            i -= 2;
            iArr2[i] = (int) (j3 >>> 1);
            i2 = (int) j3;
            if (i4 <= 0) {
                long j4 = j * j;
                long j5 = (j4 >>> 33) | ((i2 << 31) & 4294967295L);
                iArr2[0] = (int) j4;
                long j6 = iArr[1] & 4294967295L;
                long j7 = j5 + (j6 * j);
                int i5 = (int) j7;
                iArr2[1] = (i5 << 1) | (((int) (j4 >>> 32)) & 1);
                int i6 = i5 >>> 31;
                long j8 = (iArr2[2] & 4294967295L) + (j7 >>> 32);
                long j9 = iArr[2] & 4294967295L;
                long j10 = j8 + (j9 * j);
                int i7 = (int) j10;
                iArr2[2] = (i7 << 1) | i6;
                long j11 = (iArr2[3] & 4294967295L) + (j10 >>> 32) + (j9 * j6);
                long j12 = (iArr2[4] & 4294967295L) + (j11 >>> 32);
                long j13 = iArr[3] & 4294967295L;
                long j14 = (iArr2[5] & 4294967295L) + (j12 >>> 32);
                long j15 = j12 & 4294967295L;
                long j16 = (iArr2[6] & 4294967295L) + (j14 >>> 32);
                long j17 = (j11 & 4294967295L) + (j13 * j);
                int i8 = (int) j17;
                iArr2[3] = (i8 << 1) | (i7 >>> 31);
                int i9 = i8 >>> 31;
                long j18 = j15 + (j17 >>> 32) + (j13 * j6);
                long j19 = (j14 & 4294967295L) + (j18 >>> 32) + (j13 * j9);
                long j20 = j16 + (j19 >>> 32);
                long j21 = iArr[4] & 4294967295L;
                long j22 = (iArr2[7] & 4294967295L) + (j20 >>> 32);
                long j23 = j20 & 4294967295L;
                long j24 = (iArr2[8] & 4294967295L) + (j22 >>> 32);
                long j25 = (j18 & 4294967295L) + (j21 * j);
                int i10 = (int) j25;
                iArr2[4] = (i10 << 1) | i9;
                long j26 = (j19 & 4294967295L) + (j25 >>> 32) + (j21 * j6);
                long j27 = j23 + (j26 >>> 32) + (j21 * j9);
                long j28 = (j22 & 4294967295L) + (j27 >>> 32) + (j21 * j13);
                long j29 = j24 + (j28 >>> 32);
                long j30 = j28 & 4294967295L;
                long j31 = iArr[5] & 4294967295L;
                long j32 = (iArr2[9] & 4294967295L) + (j29 >>> 32);
                long j33 = j29 & 4294967295L;
                long j34 = (iArr2[10] & 4294967295L) + (j32 >>> 32);
                long j35 = (j26 & 4294967295L) + (j31 * j);
                int i11 = (int) j35;
                iArr2[5] = (i11 << 1) | (i10 >>> 31);
                long j36 = (j27 & 4294967295L) + (j35 >>> 32) + (j31 * j6);
                long j37 = j30 + (j36 >>> 32) + (j31 * j9);
                long j38 = j33 + (j37 >>> 32) + (j31 * j13);
                long j39 = (j32 & 4294967295L) + (j38 >>> 32) + (j31 * j21);
                long j40 = j34 + (j39 >>> 32);
                long j41 = j39 & 4294967295L;
                long j42 = iArr[6] & 4294967295L;
                long j43 = (iArr2[11] & 4294967295L) + (j40 >>> 32);
                long j44 = j40 & 4294967295L;
                long j45 = (iArr2[12] & 4294967295L) + (j43 >>> 32);
                long j46 = (j36 & 4294967295L) + (j42 * j);
                int i12 = (int) j46;
                iArr2[6] = (i12 << 1) | (i11 >>> 31);
                long j47 = (j37 & 4294967295L) + (j46 >>> 32) + (j42 * j6);
                long j48 = (j38 & 4294967295L) + (j47 >>> 32) + (j42 * j9);
                long j49 = j47 & 4294967295L;
                long j50 = j41 + (j48 >>> 32) + (j42 * j13);
                long j51 = j44 + (j50 >>> 32) + (j42 * j21);
                long j52 = (j43 & 4294967295L) + (j51 >>> 32) + (j42 * j31);
                long j53 = j45 + (j52 >>> 32);
                long j54 = j52 & 4294967295L;
                long j55 = iArr[7] & 4294967295L;
                long j56 = (iArr2[13] & 4294967295L) + (j53 >>> 32);
                long j57 = 4294967295L & j56;
                long j58 = j49 + (j * j55);
                int i13 = (int) j58;
                iArr2[7] = (i12 >>> 31) | (i13 << 1);
                int i14 = i13 >>> 31;
                long j59 = (j48 & 4294967295L) + (j58 >>> 32) + (j55 * j6);
                long j60 = (j50 & 4294967295L) + (j59 >>> 32) + (j55 * j9);
                long j61 = (j51 & 4294967295L) + (j60 >>> 32) + (j55 * j13);
                long j62 = j54 + (j61 >>> 32) + (j55 * j21);
                long j63 = (j53 & 4294967295L) + (j62 >>> 32) + (j55 * j31);
                long j64 = j57 + (j63 >>> 32) + (j55 * j42);
                long j65 = (iArr2[14] & 4294967295L) + (j56 >>> 32) + (j64 >>> 32);
                int i15 = (int) j59;
                iArr2[8] = i14 | (i15 << 1);
                int i16 = i15 >>> 31;
                int i17 = (int) j60;
                iArr2[9] = i16 | (i17 << 1);
                int i18 = i17 >>> 31;
                int i19 = (int) j61;
                iArr2[10] = i18 | (i19 << 1);
                int i20 = i19 >>> 31;
                int i21 = (int) j62;
                iArr2[11] = i20 | (i21 << 1);
                int i22 = i21 >>> 31;
                int i23 = (int) j63;
                iArr2[12] = i22 | (i23 << 1);
                int i24 = i23 >>> 31;
                int i25 = (int) j64;
                iArr2[13] = i24 | (i25 << 1);
                int i26 = i25 >>> 31;
                int i27 = (int) j65;
                iArr2[14] = i26 | (i27 << 1);
                iArr2[15] = (i27 >>> 31) | ((iArr2[15] + ((int) (j65 >>> 32))) << 1);
                return;
            }
            i3 = i4;
        }
    }

    public static int sub(int[] iArr, int i, int[] iArr2, int i2, int[] iArr3, int i3) {
        long j = (iArr[i] & 4294967295L) - (iArr2[i2] & 4294967295L);
        iArr3[i3] = (int) j;
        long j2 = (j >> 32) + ((iArr[i + 1] & 4294967295L) - (iArr2[i2 + 1] & 4294967295L));
        iArr3[i3 + 1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[i + 2] & 4294967295L) - (iArr2[i2 + 2] & 4294967295L));
        iArr3[i3 + 2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr[i + 3] & 4294967295L) - (iArr2[i2 + 3] & 4294967295L));
        iArr3[i3 + 3] = (int) j4;
        long j5 = (j4 >> 32) + ((iArr[i + 4] & 4294967295L) - (iArr2[i2 + 4] & 4294967295L));
        iArr3[i3 + 4] = (int) j5;
        long j6 = (j5 >> 32) + ((iArr[i + 5] & 4294967295L) - (iArr2[i2 + 5] & 4294967295L));
        iArr3[i3 + 5] = (int) j6;
        long j7 = (j6 >> 32) + ((iArr[i + 6] & 4294967295L) - (iArr2[i2 + 6] & 4294967295L));
        iArr3[i3 + 6] = (int) j7;
        long j8 = (j7 >> 32) + ((iArr[i + 7] & 4294967295L) - (iArr2[i2 + 7] & 4294967295L));
        iArr3[i3 + 7] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int sub(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = (iArr[0] & 4294967295L) - (iArr2[0] & 4294967295L);
        iArr3[0] = (int) j;
        long j2 = (j >> 32) + ((iArr[1] & 4294967295L) - (iArr2[1] & 4294967295L));
        iArr3[1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr[2] & 4294967295L) - (iArr2[2] & 4294967295L));
        iArr3[2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr[3] & 4294967295L) - (iArr2[3] & 4294967295L));
        iArr3[3] = (int) j4;
        long j5 = (j4 >> 32) + ((iArr[4] & 4294967295L) - (iArr2[4] & 4294967295L));
        iArr3[4] = (int) j5;
        long j6 = (j5 >> 32) + ((iArr[5] & 4294967295L) - (iArr2[5] & 4294967295L));
        iArr3[5] = (int) j6;
        long j7 = (j6 >> 32) + ((iArr[6] & 4294967295L) - (iArr2[6] & 4294967295L));
        iArr3[6] = (int) j7;
        long j8 = (j7 >> 32) + ((iArr[7] & 4294967295L) - (iArr2[7] & 4294967295L));
        iArr3[7] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int subBothFrom(int[] iArr, int[] iArr2, int[] iArr3) {
        long j = ((iArr3[0] & 4294967295L) - (iArr[0] & 4294967295L)) - (iArr2[0] & 4294967295L);
        iArr3[0] = (int) j;
        long j2 = (j >> 32) + (((iArr3[1] & 4294967295L) - (iArr[1] & 4294967295L)) - (iArr2[1] & 4294967295L));
        iArr3[1] = (int) j2;
        long j3 = (j2 >> 32) + (((iArr3[2] & 4294967295L) - (iArr[2] & 4294967295L)) - (iArr2[2] & 4294967295L));
        iArr3[2] = (int) j3;
        long j4 = (j3 >> 32) + (((iArr3[3] & 4294967295L) - (iArr[3] & 4294967295L)) - (iArr2[3] & 4294967295L));
        iArr3[3] = (int) j4;
        long j5 = (j4 >> 32) + (((iArr3[4] & 4294967295L) - (iArr[4] & 4294967295L)) - (iArr2[4] & 4294967295L));
        iArr3[4] = (int) j5;
        long j6 = (j5 >> 32) + (((iArr3[5] & 4294967295L) - (iArr[5] & 4294967295L)) - (iArr2[5] & 4294967295L));
        iArr3[5] = (int) j6;
        long j7 = (j6 >> 32) + (((iArr3[6] & 4294967295L) - (iArr[6] & 4294967295L)) - (iArr2[6] & 4294967295L));
        iArr3[6] = (int) j7;
        long j8 = (j7 >> 32) + (((iArr3[7] & 4294967295L) - (iArr[7] & 4294967295L)) - (iArr2[7] & 4294967295L));
        iArr3[7] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int subFrom(int[] iArr, int i, int[] iArr2, int i2) {
        long j = (iArr2[i2] & 4294967295L) - (iArr[i] & 4294967295L);
        iArr2[i2] = (int) j;
        int i3 = i2 + 1;
        long j2 = (j >> 32) + ((iArr2[i3] & 4294967295L) - (iArr[i + 1] & 4294967295L));
        iArr2[i3] = (int) j2;
        int i4 = i2 + 2;
        long j3 = (j2 >> 32) + ((iArr2[i4] & 4294967295L) - (iArr[i + 2] & 4294967295L));
        iArr2[i4] = (int) j3;
        int i5 = i2 + 3;
        long j4 = (j3 >> 32) + ((iArr2[i5] & 4294967295L) - (iArr[i + 3] & 4294967295L));
        iArr2[i5] = (int) j4;
        int i6 = i2 + 4;
        long j5 = (j4 >> 32) + ((iArr2[i6] & 4294967295L) - (iArr[i + 4] & 4294967295L));
        iArr2[i6] = (int) j5;
        int i7 = i2 + 5;
        long j6 = (j5 >> 32) + ((iArr2[i7] & 4294967295L) - (iArr[i + 5] & 4294967295L));
        iArr2[i7] = (int) j6;
        int i8 = i2 + 6;
        long j7 = (j6 >> 32) + ((iArr2[i8] & 4294967295L) - (iArr[i + 6] & 4294967295L));
        iArr2[i8] = (int) j7;
        int i9 = i2 + 7;
        long j8 = (j7 >> 32) + ((iArr2[i9] & 4294967295L) - (iArr[i + 7] & 4294967295L));
        iArr2[i9] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int subFrom(int[] iArr, int i, int[] iArr2, int i2, int i3) {
        long j = (i3 & 4294967295L) + ((iArr2[i2] & 4294967295L) - (iArr[i] & 4294967295L));
        iArr2[i2] = (int) j;
        int i4 = i2 + 1;
        long j2 = (j >> 32) + ((iArr2[i4] & 4294967295L) - (iArr[i + 1] & 4294967295L));
        iArr2[i4] = (int) j2;
        int i5 = i2 + 2;
        long j3 = (j2 >> 32) + ((iArr2[i5] & 4294967295L) - (iArr[i + 2] & 4294967295L));
        iArr2[i5] = (int) j3;
        int i6 = i2 + 3;
        long j4 = (j3 >> 32) + ((iArr2[i6] & 4294967295L) - (iArr[i + 3] & 4294967295L));
        iArr2[i6] = (int) j4;
        int i7 = i2 + 4;
        long j5 = (j4 >> 32) + ((iArr2[i7] & 4294967295L) - (iArr[i + 4] & 4294967295L));
        iArr2[i7] = (int) j5;
        int i8 = i2 + 5;
        long j6 = (j5 >> 32) + ((iArr2[i8] & 4294967295L) - (iArr[i + 5] & 4294967295L));
        iArr2[i8] = (int) j6;
        int i9 = i2 + 6;
        long j7 = (j6 >> 32) + ((iArr2[i9] & 4294967295L) - (iArr[i + 6] & 4294967295L));
        iArr2[i9] = (int) j7;
        int i10 = i2 + 7;
        long j8 = (j7 >> 32) + ((iArr2[i10] & 4294967295L) - (iArr[i + 7] & 4294967295L));
        iArr2[i10] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int subFrom(int[] iArr, int[] iArr2) {
        long j = (iArr2[0] & 4294967295L) - (iArr[0] & 4294967295L);
        iArr2[0] = (int) j;
        long j2 = (j >> 32) + ((iArr2[1] & 4294967295L) - (iArr[1] & 4294967295L));
        iArr2[1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr2[2] & 4294967295L) - (iArr[2] & 4294967295L));
        iArr2[2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr2[3] & 4294967295L) - (iArr[3] & 4294967295L));
        iArr2[3] = (int) j4;
        long j5 = (j4 >> 32) + ((iArr2[4] & 4294967295L) - (iArr[4] & 4294967295L));
        iArr2[4] = (int) j5;
        long j6 = (j5 >> 32) + ((iArr2[5] & 4294967295L) - (iArr[5] & 4294967295L));
        iArr2[5] = (int) j6;
        long j7 = (j6 >> 32) + ((iArr2[6] & 4294967295L) - (iArr[6] & 4294967295L));
        iArr2[6] = (int) j7;
        long j8 = (j7 >> 32) + ((iArr2[7] & 4294967295L) - (4294967295L & iArr[7]));
        iArr2[7] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static int subFrom(int[] iArr, int[] iArr2, int i) {
        long j = (i & 4294967295L) + ((iArr2[0] & 4294967295L) - (iArr[0] & 4294967295L));
        iArr2[0] = (int) j;
        long j2 = (j >> 32) + ((iArr2[1] & 4294967295L) - (iArr[1] & 4294967295L));
        iArr2[1] = (int) j2;
        long j3 = (j2 >> 32) + ((iArr2[2] & 4294967295L) - (iArr[2] & 4294967295L));
        iArr2[2] = (int) j3;
        long j4 = (j3 >> 32) + ((iArr2[3] & 4294967295L) - (iArr[3] & 4294967295L));
        iArr2[3] = (int) j4;
        long j5 = (j4 >> 32) + ((iArr2[4] & 4294967295L) - (iArr[4] & 4294967295L));
        iArr2[4] = (int) j5;
        long j6 = (j5 >> 32) + ((iArr2[5] & 4294967295L) - (iArr[5] & 4294967295L));
        iArr2[5] = (int) j6;
        long j7 = (j6 >> 32) + ((iArr2[6] & 4294967295L) - (iArr[6] & 4294967295L));
        iArr2[6] = (int) j7;
        long j8 = (j7 >> 32) + ((iArr2[7] & 4294967295L) - (4294967295L & iArr[7]));
        iArr2[7] = (int) j8;
        return (int) (j8 >> 32);
    }

    public static BigInteger toBigInteger(int[] iArr) {
        byte[] bArr = new byte[32];
        for (int i = 0; i < 8; i++) {
            int i2 = iArr[i];
            if (i2 != 0) {
                Pack.intToBigEndian(i2, bArr, (7 - i) << 2);
            }
        }
        return new BigInteger(1, bArr);
    }

    public static BigInteger toBigInteger64(long[] jArr) {
        byte[] bArr = new byte[32];
        for (int i = 0; i < 4; i++) {
            long j = jArr[i];
            if (j != 0) {
                Pack.longToBigEndian(j, bArr, (3 - i) << 3);
            }
        }
        return new BigInteger(1, bArr);
    }

    public static void zero(int[] iArr) {
        iArr[0] = 0;
        iArr[1] = 0;
        iArr[2] = 0;
        iArr[3] = 0;
        iArr[4] = 0;
        iArr[5] = 0;
        iArr[6] = 0;
        iArr[7] = 0;
    }
}