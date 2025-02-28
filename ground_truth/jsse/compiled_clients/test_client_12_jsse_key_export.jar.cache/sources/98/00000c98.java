package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat384;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP384R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP384R1Field.class */
public class SecP384R1Field {

    /* renamed from: M */
    private static final long f743M = 4294967295L;

    /* renamed from: P */
    static final int[] f744P = {-1, 0, 0, -1, -2, -1, -1, -1, -1, -1, -1, -1};
    private static final int[] PExt = {1, -2, 0, 2, 0, -2, 0, 2, 1, 0, 0, 0, -2, 1, 0, -2, -3, -1, -1, -1, -1, -1, -1, -1};
    private static final int[] PExtInv = {-1, 1, -1, -3, -1, 1, -1, -3, -2, -1, -1, -1, 1, -2, -1, 1, 2};
    private static final int P11 = -1;
    private static final int PExt23 = -1;

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.add(12, iArr, iArr2, iArr3) != 0 || (iArr3[11] == -1 && Nat.gte(12, iArr3, f744P))) {
            addPInvTo(iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat.add(24, iArr, iArr2, iArr3) != 0 || (iArr3[23] == -1 && Nat.gte(24, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(24, iArr3, PExtInv.length);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        if (Nat.inc(12, iArr, iArr2) != 0 || (iArr2[11] == -1 && Nat.gte(12, iArr2, f744P))) {
            addPInvTo(iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat.fromBigInteger(384, bigInteger);
        if (fromBigInteger[11] == -1 && Nat.gte(12, fromBigInteger, f744P)) {
            Nat.subFrom(12, f744P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(12, iArr, 0, iArr2);
        } else {
            Nat.shiftDownBit(12, iArr2, Nat.add(12, iArr, f744P, iArr2));
        }
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f744P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 12; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] create = Nat.create(24);
        Nat384.mul(iArr, iArr2, create);
        reduce(create, iArr3);
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat.sub(12, f744P, f744P, iArr2);
        } else {
            Nat.sub(12, f744P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[48];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 12);
        } while (0 == Nat.lessThan(12, iArr, f744P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        long j = iArr[16] & f743M;
        long j2 = iArr[17] & f743M;
        long j3 = iArr[18] & f743M;
        long j4 = iArr[19] & f743M;
        long j5 = iArr[20] & f743M;
        long j6 = iArr[21] & f743M;
        long j7 = iArr[22] & f743M;
        long j8 = iArr[23] & f743M;
        long j9 = ((iArr[12] & f743M) + j5) - 1;
        long j10 = (iArr[13] & f743M) + j7;
        long j11 = (iArr[14] & f743M) + j7 + j8;
        long j12 = (iArr[15] & f743M) + j8;
        long j13 = j2 + j6;
        long j14 = j6 - j8;
        long j15 = j7 - j8;
        long j16 = j9 + j14;
        long j17 = 0 + (iArr[0] & f743M) + j16;
        iArr2[0] = (int) j17;
        long j18 = (j17 >> 32) + (((iArr[1] & f743M) + j8) - j9) + j10;
        iArr2[1] = (int) j18;
        long j19 = (j18 >> 32) + (((iArr[2] & f743M) - j6) - j10) + j11;
        iArr2[2] = (int) j19;
        long j20 = (j19 >> 32) + ((iArr[3] & f743M) - j11) + j12 + j16;
        iArr2[3] = (int) j20;
        long j21 = (j20 >> 32) + (((((iArr[4] & f743M) + j) + j6) + j10) - j12) + j16;
        iArr2[4] = (int) j21;
        long j22 = (j21 >> 32) + ((iArr[5] & f743M) - j) + j10 + j11 + j13;
        iArr2[5] = (int) j22;
        long j23 = (j22 >> 32) + (((iArr[6] & f743M) + j3) - j2) + j11 + j12;
        iArr2[6] = (int) j23;
        long j24 = (j23 >> 32) + ((((iArr[7] & f743M) + j) + j4) - j3) + j12;
        iArr2[7] = (int) j24;
        long j25 = (j24 >> 32) + (((((iArr[8] & f743M) + j) + j2) + j5) - j4);
        iArr2[8] = (int) j25;
        long j26 = (j25 >> 32) + (((iArr[9] & f743M) + j3) - j5) + j13;
        iArr2[9] = (int) j26;
        long j27 = (j26 >> 32) + ((((iArr[10] & f743M) + j3) + j4) - j14) + j15;
        iArr2[10] = (int) j27;
        long j28 = (j27 >> 32) + ((((iArr[11] & f743M) + j4) + j5) - j15);
        iArr2[11] = (int) j28;
        reduce32((int) ((j28 >> 32) + 1), iArr2);
    }

    public static void reduce32(int i, int[] iArr) {
        long j = 0;
        if (i != 0) {
            long j2 = i & f743M;
            long j3 = 0 + (iArr[0] & f743M) + j2;
            iArr[0] = (int) j3;
            long j4 = (j3 >> 32) + ((iArr[1] & f743M) - j2);
            iArr[1] = (int) j4;
            long j5 = j4 >> 32;
            if (j5 != 0) {
                long j6 = j5 + (iArr[2] & f743M);
                iArr[2] = (int) j6;
                j5 = j6 >> 32;
            }
            long j7 = j5 + (iArr[3] & f743M) + j2;
            iArr[3] = (int) j7;
            long j8 = (j7 >> 32) + (iArr[4] & f743M) + j2;
            iArr[4] = (int) j8;
            j = j8 >> 32;
        }
        if ((j == 0 || Nat.incAt(12, iArr, 5) == 0) && !(iArr[11] == -1 && Nat.gte(12, iArr, f744P))) {
            return;
        }
        addPInvTo(iArr);
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] create = Nat.create(24);
        Nat384.square(iArr, create);
        reduce(create, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] create = Nat.create(24);
        Nat384.square(iArr, create);
        reduce(create, iArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            Nat384.square(iArr2, create);
            reduce(create, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(12, iArr, iArr2, iArr3) != 0) {
            subPInvFrom(iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(24, iArr, iArr2, iArr3) == 0 || Nat.subFrom(PExtInv.length, PExtInv, iArr3) == 0) {
            return;
        }
        Nat.decAt(24, iArr3, PExtInv.length);
    }

    public static void twice(int[] iArr, int[] iArr2) {
        if (Nat.shiftUpBit(12, iArr, 0, iArr2) != 0 || (iArr2[11] == -1 && Nat.gte(12, iArr2, f744P))) {
            addPInvTo(iArr2);
        }
    }

    private static void addPInvTo(int[] iArr) {
        long j = (iArr[0] & f743M) + 1;
        iArr[0] = (int) j;
        long j2 = (j >> 32) + ((iArr[1] & f743M) - 1);
        iArr[1] = (int) j2;
        long j3 = j2 >> 32;
        if (j3 != 0) {
            long j4 = j3 + (iArr[2] & f743M);
            iArr[2] = (int) j4;
            j3 = j4 >> 32;
        }
        long j5 = j3 + (iArr[3] & f743M) + 1;
        iArr[3] = (int) j5;
        long j6 = (j5 >> 32) + (iArr[4] & f743M) + 1;
        iArr[4] = (int) j6;
        if ((j6 >> 32) != 0) {
            Nat.incAt(12, iArr, 5);
        }
    }

    private static void subPInvFrom(int[] iArr) {
        long j = (iArr[0] & f743M) - 1;
        iArr[0] = (int) j;
        long j2 = (j >> 32) + (iArr[1] & f743M) + 1;
        iArr[1] = (int) j2;
        long j3 = j2 >> 32;
        if (j3 != 0) {
            long j4 = j3 + (iArr[2] & f743M);
            iArr[2] = (int) j4;
            j3 = j4 >> 32;
        }
        long j5 = j3 + ((iArr[3] & f743M) - 1);
        iArr[3] = (int) j5;
        long j6 = (j5 >> 32) + ((iArr[4] & f743M) - 1);
        iArr[4] = (int) j6;
        if ((j6 >> 32) != 0) {
            Nat.decAt(12, iArr, 5);
        }
    }
}