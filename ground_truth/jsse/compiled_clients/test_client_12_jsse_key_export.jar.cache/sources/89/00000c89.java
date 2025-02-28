package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat224;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP224R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP224R1Field.class */
public class SecP224R1Field {

    /* renamed from: M */
    private static final long f726M = 4294967295L;

    /* renamed from: P */
    static final int[] f727P = {1, 0, 0, -1, -1, -1, -1};
    private static final int[] PExt = {1, 0, 0, -2, -1, -1, 0, 2, 0, 0, -2, -1, -1, -1};
    private static final int[] PExtInv = {-1, -1, -1, 1, 0, 0, -1, -3, -1, -1, 1};

    /* renamed from: P6 */
    private static final int f728P6 = -1;
    private static final int PExt13 = -1;

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat224.add(iArr, iArr2, iArr3) != 0 || (iArr3[6] == -1 && Nat224.gte(iArr3, f727P))) {
            addPInvTo(iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat.add(14, iArr, iArr2, iArr3) != 0 || (iArr3[13] == -1 && Nat.gte(14, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(14, iArr3, PExtInv.length);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        if (Nat.inc(7, iArr, iArr2) != 0 || (iArr2[6] == -1 && Nat224.gte(iArr2, f727P))) {
            addPInvTo(iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat224.fromBigInteger(bigInteger);
        if (fromBigInteger[6] == -1 && Nat224.gte(fromBigInteger, f727P)) {
            Nat224.subFrom(f727P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(7, iArr, 0, iArr2);
        } else {
            Nat.shiftDownBit(7, iArr2, Nat224.add(iArr, f727P, iArr2));
        }
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f727P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 7; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] createExt = Nat224.createExt();
        Nat224.mul(iArr, iArr2, createExt);
        reduce(createExt, iArr3);
    }

    public static void multiplyAddToExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat224.mulAddTo(iArr, iArr2, iArr3) != 0 || (iArr3[13] == -1 && Nat.gte(14, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(14, iArr3, PExtInv.length);
        }
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat224.sub(f727P, f727P, iArr2);
        } else {
            Nat224.sub(f727P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[28];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 7);
        } while (0 == Nat.lessThan(7, iArr, f727P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        long j = iArr[10] & f726M;
        long j2 = iArr[11] & f726M;
        long j3 = iArr[12] & f726M;
        long j4 = iArr[13] & f726M;
        long j5 = ((iArr[7] & f726M) + j2) - 1;
        long j6 = (iArr[8] & f726M) + j3;
        long j7 = (iArr[9] & f726M) + j4;
        long j8 = 0 + ((iArr[0] & f726M) - j5);
        long j9 = j8 & f726M;
        long j10 = (j8 >> 32) + ((iArr[1] & f726M) - j6);
        iArr2[1] = (int) j10;
        long j11 = (j10 >> 32) + ((iArr[2] & f726M) - j7);
        iArr2[2] = (int) j11;
        long j12 = (j11 >> 32) + (((iArr[3] & f726M) + j5) - j);
        long j13 = j12 & f726M;
        long j14 = (j12 >> 32) + (((iArr[4] & f726M) + j6) - j2);
        iArr2[4] = (int) j14;
        long j15 = (j14 >> 32) + (((iArr[5] & f726M) + j7) - j3);
        iArr2[5] = (int) j15;
        long j16 = (j15 >> 32) + (((iArr[6] & f726M) + j) - j4);
        iArr2[6] = (int) j16;
        long j17 = (j16 >> 32) + 1;
        long j18 = j13 + j17;
        long j19 = j9 - j17;
        iArr2[0] = (int) j19;
        long j20 = j19 >> 32;
        if (j20 != 0) {
            long j21 = j20 + (iArr2[1] & f726M);
            iArr2[1] = (int) j21;
            long j22 = (j21 >> 32) + (iArr2[2] & f726M);
            iArr2[2] = (int) j22;
            j18 += j22 >> 32;
        }
        iArr2[3] = (int) j18;
        if (((j18 >> 32) == 0 || Nat.incAt(7, iArr2, 4) == 0) && !(iArr2[6] == -1 && Nat224.gte(iArr2, f727P))) {
            return;
        }
        addPInvTo(iArr2);
    }

    public static void reduce32(int i, int[] iArr) {
        long j = 0;
        if (i != 0) {
            long j2 = i & f726M;
            long j3 = 0 + ((iArr[0] & f726M) - j2);
            iArr[0] = (int) j3;
            long j4 = j3 >> 32;
            if (j4 != 0) {
                long j5 = j4 + (iArr[1] & f726M);
                iArr[1] = (int) j5;
                long j6 = (j5 >> 32) + (iArr[2] & f726M);
                iArr[2] = (int) j6;
                j4 = j6 >> 32;
            }
            long j7 = j4 + (iArr[3] & f726M) + j2;
            iArr[3] = (int) j7;
            j = j7 >> 32;
        }
        if ((j == 0 || Nat.incAt(7, iArr, 4) == 0) && !(iArr[6] == -1 && Nat224.gte(iArr, f727P))) {
            return;
        }
        addPInvTo(iArr);
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] createExt = Nat224.createExt();
        Nat224.square(iArr, createExt);
        reduce(createExt, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] createExt = Nat224.createExt();
        Nat224.square(iArr, createExt);
        reduce(createExt, iArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            Nat224.square(iArr2, createExt);
            reduce(createExt, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat224.sub(iArr, iArr2, iArr3) != 0) {
            subPInvFrom(iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(14, iArr, iArr2, iArr3) == 0 || Nat.subFrom(PExtInv.length, PExtInv, iArr3) == 0) {
            return;
        }
        Nat.decAt(14, iArr3, PExtInv.length);
    }

    public static void twice(int[] iArr, int[] iArr2) {
        if (Nat.shiftUpBit(7, iArr, 0, iArr2) != 0 || (iArr2[6] == -1 && Nat224.gte(iArr2, f727P))) {
            addPInvTo(iArr2);
        }
    }

    private static void addPInvTo(int[] iArr) {
        long j = (iArr[0] & f726M) - 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f726M);
            iArr[1] = (int) j3;
            long j4 = (j3 >> 32) + (iArr[2] & f726M);
            iArr[2] = (int) j4;
            j2 = j4 >> 32;
        }
        long j5 = j2 + (iArr[3] & f726M) + 1;
        iArr[3] = (int) j5;
        if ((j5 >> 32) != 0) {
            Nat.incAt(7, iArr, 4);
        }
    }

    private static void subPInvFrom(int[] iArr) {
        long j = (iArr[0] & f726M) + 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f726M);
            iArr[1] = (int) j3;
            long j4 = (j3 >> 32) + (iArr[2] & f726M);
            iArr[2] = (int) j4;
            j2 = j4 >> 32;
        }
        long j5 = j2 + ((iArr[3] & f726M) - 1);
        iArr[3] = (int) j5;
        if ((j5 >> 32) != 0) {
            Nat.decAt(7, iArr, 4);
        }
    }
}