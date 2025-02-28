package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP256R1Field.class */
public class SecP256R1Field {

    /* renamed from: M */
    private static final long f737M = 4294967295L;
    private static final int PExt15s1 = Integer.MAX_VALUE;

    /* renamed from: P7 */
    private static final int f739P7 = -1;

    /* renamed from: P */
    static final int[] f738P = {f739P7, f739P7, f739P7, 0, 0, 0, 1, f739P7};
    private static final int[] PExt = {1, 0, 0, -2, f739P7, f739P7, -2, 1, -2, 1, -2, 1, 1, -2, 2, -2};

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat256.add(iArr, iArr2, iArr3) != 0 || (iArr3[7] == f739P7 && Nat256.gte(iArr3, f738P))) {
            addPInvTo(iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.add(16, iArr, iArr2, iArr3) != 0 || ((iArr3[15] >>> 1) >= PExt15s1 && Nat.gte(16, iArr3, PExt))) {
            Nat.subFrom(16, PExt, iArr3);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        if (Nat.inc(8, iArr, iArr2) != 0 || (iArr2[7] == f739P7 && Nat256.gte(iArr2, f738P))) {
            addPInvTo(iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat256.fromBigInteger(bigInteger);
        if (fromBigInteger[7] == f739P7 && Nat256.gte(fromBigInteger, f738P)) {
            Nat256.subFrom(f738P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(8, iArr, 0, iArr2);
        } else {
            Nat.shiftDownBit(8, iArr2, Nat256.add(iArr, f738P, iArr2));
        }
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f738P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 8; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] createExt = Nat256.createExt();
        Nat256.mul(iArr, iArr2, createExt);
        reduce(createExt, iArr3);
    }

    public static void multiplyAddToExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat256.mulAddTo(iArr, iArr2, iArr3) != 0 || ((iArr3[15] >>> 1) >= PExt15s1 && Nat.gte(16, iArr3, PExt))) {
            Nat.subFrom(16, PExt, iArr3);
        }
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat256.sub(f738P, f738P, iArr2);
        } else {
            Nat256.sub(f738P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[32];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 8);
        } while (0 == Nat.lessThan(8, iArr, f738P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        long j = iArr[8] & f737M;
        long j2 = iArr[9] & f737M;
        long j3 = iArr[10] & f737M;
        long j4 = iArr[11] & f737M;
        long j5 = iArr[12] & f737M;
        long j6 = iArr[13] & f737M;
        long j7 = iArr[14] & f737M;
        long j8 = iArr[15] & f737M;
        long j9 = j - 6;
        long j10 = j9 + j2;
        long j11 = j2 + j3;
        long j12 = (j3 + j4) - j8;
        long j13 = j4 + j5;
        long j14 = j5 + j6;
        long j15 = j6 + j7;
        long j16 = j7 + j8;
        long j17 = j15 - j10;
        long j18 = 0 + (((iArr[0] & f737M) - j13) - j17);
        iArr2[0] = (int) j18;
        long j19 = (j18 >> 32) + ((((iArr[1] & f737M) + j11) - j14) - j16);
        iArr2[1] = (int) j19;
        long j20 = (j19 >> 32) + (((iArr[2] & f737M) + j12) - j15);
        iArr2[2] = (int) j20;
        long j21 = (j20 >> 32) + ((((iArr[3] & f737M) + (j13 << 1)) + j17) - j16);
        iArr2[3] = (int) j21;
        long j22 = (j21 >> 32) + ((((iArr[4] & f737M) + (j14 << 1)) + j7) - j11);
        iArr2[4] = (int) j22;
        long j23 = (j22 >> 32) + (((iArr[5] & f737M) + (j15 << 1)) - j12);
        iArr2[5] = (int) j23;
        long j24 = (j23 >> 32) + (iArr[6] & f737M) + (j16 << 1) + j17;
        iArr2[6] = (int) j24;
        long j25 = (j24 >> 32) + (((((iArr[7] & f737M) + (j8 << 1)) + j9) - j12) - j14);
        iArr2[7] = (int) j25;
        reduce32((int) ((j25 >> 32) + 6), iArr2);
    }

    public static void reduce32(int i, int[] iArr) {
        long j = 0;
        if (i != 0) {
            long j2 = i & f737M;
            long j3 = 0 + (iArr[0] & f737M) + j2;
            iArr[0] = (int) j3;
            long j4 = j3 >> 32;
            if (j4 != 0) {
                long j5 = j4 + (iArr[1] & f737M);
                iArr[1] = (int) j5;
                long j6 = (j5 >> 32) + (iArr[2] & f737M);
                iArr[2] = (int) j6;
                j4 = j6 >> 32;
            }
            long j7 = j4 + ((iArr[3] & f737M) - j2);
            iArr[3] = (int) j7;
            long j8 = j7 >> 32;
            if (j8 != 0) {
                long j9 = j8 + (iArr[4] & f737M);
                iArr[4] = (int) j9;
                long j10 = (j9 >> 32) + (iArr[5] & f737M);
                iArr[5] = (int) j10;
                j8 = j10 >> 32;
            }
            long j11 = j8 + ((iArr[6] & f737M) - j2);
            iArr[6] = (int) j11;
            long j12 = (j11 >> 32) + (iArr[7] & f737M) + j2;
            iArr[7] = (int) j12;
            j = j12 >> 32;
        }
        if (j != 0 || (iArr[7] == f739P7 && Nat256.gte(iArr, f738P))) {
            addPInvTo(iArr);
        }
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] createExt = Nat256.createExt();
        Nat256.square(iArr, createExt);
        reduce(createExt, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] createExt = Nat256.createExt();
        Nat256.square(iArr, createExt);
        reduce(createExt, iArr2);
        while (true) {
            i += f739P7;
            if (i <= 0) {
                return;
            }
            Nat256.square(iArr2, createExt);
            reduce(createExt, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat256.sub(iArr, iArr2, iArr3) != 0) {
            subPInvFrom(iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(16, iArr, iArr2, iArr3) != 0) {
            Nat.addTo(16, PExt, iArr3);
        }
    }

    public static void twice(int[] iArr, int[] iArr2) {
        if (Nat.shiftUpBit(8, iArr, 0, iArr2) != 0 || (iArr2[7] == f739P7 && Nat256.gte(iArr2, f738P))) {
            addPInvTo(iArr2);
        }
    }

    private static void addPInvTo(int[] iArr) {
        long j = (iArr[0] & f737M) + 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f737M);
            iArr[1] = (int) j3;
            long j4 = (j3 >> 32) + (iArr[2] & f737M);
            iArr[2] = (int) j4;
            j2 = j4 >> 32;
        }
        long j5 = j2 + ((iArr[3] & f737M) - 1);
        iArr[3] = (int) j5;
        long j6 = j5 >> 32;
        if (j6 != 0) {
            long j7 = j6 + (iArr[4] & f737M);
            iArr[4] = (int) j7;
            long j8 = (j7 >> 32) + (iArr[5] & f737M);
            iArr[5] = (int) j8;
            j6 = j8 >> 32;
        }
        long j9 = j6 + ((iArr[6] & f737M) - 1);
        iArr[6] = (int) j9;
        iArr[7] = (int) ((j9 >> 32) + (iArr[7] & f737M) + 1);
    }

    private static void subPInvFrom(int[] iArr) {
        long j = (iArr[0] & f737M) - 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f737M);
            iArr[1] = (int) j3;
            long j4 = (j3 >> 32) + (iArr[2] & f737M);
            iArr[2] = (int) j4;
            j2 = j4 >> 32;
        }
        long j5 = j2 + (iArr[3] & f737M) + 1;
        iArr[3] = (int) j5;
        long j6 = j5 >> 32;
        if (j6 != 0) {
            long j7 = j6 + (iArr[4] & f737M);
            iArr[4] = (int) j7;
            long j8 = (j7 >> 32) + (iArr[5] & f737M);
            iArr[5] = (int) j8;
            j6 = j8 >> 32;
        }
        long j9 = j6 + (iArr[6] & f737M) + 1;
        iArr[6] = (int) j9;
        iArr[7] = (int) ((j9 >> 32) + ((iArr[7] & f737M) - 1));
    }
}