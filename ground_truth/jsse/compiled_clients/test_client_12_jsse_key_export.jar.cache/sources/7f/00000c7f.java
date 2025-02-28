package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP192R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP192R1Field.class */
public class SecP192R1Field {

    /* renamed from: M */
    private static final long f715M = 4294967295L;

    /* renamed from: P */
    static final int[] f716P = {-1, -1, -2, -1, -1, -1};
    private static final int[] PExt = {1, 0, 2, 0, 1, 0, -2, -1, -3, -1, -1, -1};
    private static final int[] PExtInv = {-1, -1, -3, -1, -2, -1, 1, 0, 2};

    /* renamed from: P5 */
    private static final int f717P5 = -1;
    private static final int PExt11 = -1;

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat192.add(iArr, iArr2, iArr3) != 0 || (iArr3[5] == -1 && Nat192.gte(iArr3, f716P))) {
            addPInvTo(iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat.add(12, iArr, iArr2, iArr3) != 0 || (iArr3[11] == -1 && Nat.gte(12, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(12, iArr3, PExtInv.length);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        if (Nat.inc(6, iArr, iArr2) != 0 || (iArr2[5] == -1 && Nat192.gte(iArr2, f716P))) {
            addPInvTo(iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat192.fromBigInteger(bigInteger);
        if (fromBigInteger[5] == -1 && Nat192.gte(fromBigInteger, f716P)) {
            Nat192.subFrom(f716P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(6, iArr, 0, iArr2);
        } else {
            Nat.shiftDownBit(6, iArr2, Nat192.add(iArr, f716P, iArr2));
        }
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f716P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 6; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] createExt = Nat192.createExt();
        Nat192.mul(iArr, iArr2, createExt);
        reduce(createExt, iArr3);
    }

    public static void multiplyAddToExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat192.mulAddTo(iArr, iArr2, iArr3) != 0 || (iArr3[11] == -1 && Nat.gte(12, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(12, iArr3, PExtInv.length);
        }
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat192.sub(f716P, f716P, iArr2);
        } else {
            Nat192.sub(f716P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[24];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 6);
        } while (0 == Nat.lessThan(6, iArr, f716P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        long j = iArr[6] & f715M;
        long j2 = iArr[7] & f715M;
        long j3 = iArr[8] & f715M;
        long j4 = iArr[9] & f715M;
        long j5 = iArr[10] & f715M;
        long j6 = j + j5;
        long j7 = j2 + (iArr[11] & f715M);
        long j8 = 0 + (iArr[0] & f715M) + j6;
        int i = (int) j8;
        long j9 = (j8 >> 32) + (iArr[1] & f715M) + j7;
        iArr2[1] = (int) j9;
        long j10 = j9 >> 32;
        long j11 = j6 + j3;
        long j12 = j7 + j4;
        long j13 = j10 + (iArr[2] & f715M) + j11;
        long j14 = j13 & f715M;
        long j15 = (j13 >> 32) + (iArr[3] & f715M) + j12;
        iArr2[3] = (int) j15;
        long j16 = j15 >> 32;
        long j17 = j11 - j;
        long j18 = j12 - j2;
        long j19 = j16 + (iArr[4] & f715M) + j17;
        iArr2[4] = (int) j19;
        long j20 = (j19 >> 32) + (iArr[5] & f715M) + j18;
        iArr2[5] = (int) j20;
        long j21 = j20 >> 32;
        long j22 = j14 + j21;
        long j23 = j21 + (i & f715M);
        iArr2[0] = (int) j23;
        long j24 = j23 >> 32;
        if (j24 != 0) {
            long j25 = j24 + (iArr2[1] & f715M);
            iArr2[1] = (int) j25;
            j22 += j25 >> 32;
        }
        iArr2[2] = (int) j22;
        if (((j22 >> 32) == 0 || Nat.incAt(6, iArr2, 3) == 0) && !(iArr2[5] == -1 && Nat192.gte(iArr2, f716P))) {
            return;
        }
        addPInvTo(iArr2);
    }

    public static void reduce32(int i, int[] iArr) {
        long j = 0;
        if (i != 0) {
            long j2 = i & f715M;
            long j3 = 0 + (iArr[0] & f715M) + j2;
            iArr[0] = (int) j3;
            long j4 = j3 >> 32;
            if (j4 != 0) {
                long j5 = j4 + (iArr[1] & f715M);
                iArr[1] = (int) j5;
                j4 = j5 >> 32;
            }
            long j6 = j4 + (iArr[2] & f715M) + j2;
            iArr[2] = (int) j6;
            j = j6 >> 32;
        }
        if ((j == 0 || Nat.incAt(6, iArr, 3) == 0) && !(iArr[5] == -1 && Nat192.gte(iArr, f716P))) {
            return;
        }
        addPInvTo(iArr);
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] createExt = Nat192.createExt();
        Nat192.square(iArr, createExt);
        reduce(createExt, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] createExt = Nat192.createExt();
        Nat192.square(iArr, createExt);
        reduce(createExt, iArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            Nat192.square(iArr2, createExt);
            reduce(createExt, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat192.sub(iArr, iArr2, iArr3) != 0) {
            subPInvFrom(iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(12, iArr, iArr2, iArr3) == 0 || Nat.subFrom(PExtInv.length, PExtInv, iArr3) == 0) {
            return;
        }
        Nat.decAt(12, iArr3, PExtInv.length);
    }

    public static void twice(int[] iArr, int[] iArr2) {
        if (Nat.shiftUpBit(6, iArr, 0, iArr2) != 0 || (iArr2[5] == -1 && Nat192.gte(iArr2, f716P))) {
            addPInvTo(iArr2);
        }
    }

    private static void addPInvTo(int[] iArr) {
        long j = (iArr[0] & f715M) + 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f715M);
            iArr[1] = (int) j3;
            j2 = j3 >> 32;
        }
        long j4 = j2 + (iArr[2] & f715M) + 1;
        iArr[2] = (int) j4;
        if ((j4 >> 32) != 0) {
            Nat.incAt(6, iArr, 3);
        }
    }

    private static void subPInvFrom(int[] iArr) {
        long j = (iArr[0] & f715M) - 1;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            long j3 = j2 + (iArr[1] & f715M);
            iArr[1] = (int) j3;
            j2 = j3 >> 32;
        }
        long j4 = j2 + ((iArr[2] & f715M) - 1);
        iArr[2] = (int) j4;
        if ((j4 >> 32) != 0) {
            Nat.decAt(6, iArr, 3);
        }
    }
}