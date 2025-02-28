package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat160;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP160R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP160R1Field.class */
public class SecP160R1Field {

    /* renamed from: M */
    private static final long f699M = 4294967295L;

    /* renamed from: P */
    static final int[] f700P = {Integer.MAX_VALUE, -1, -1, -1, -1};
    private static final int[] PExt = {1, 1073741825, 0, 0, 0, -2, -2, -1, -1, -1};
    private static final int[] PExtInv = {-1, -1073741826, -1, -1, -1, 1, 1};

    /* renamed from: P4 */
    private static final int f701P4 = -1;
    private static final int PExt9 = -1;
    private static final int PInv = -2147483647;

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat160.add(iArr, iArr2, iArr3) != 0 || (iArr3[4] == -1 && Nat160.gte(iArr3, f700P))) {
            Nat.addWordTo(5, PInv, iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat.add(10, iArr, iArr2, iArr3) != 0 || (iArr3[9] == -1 && Nat.gte(10, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(10, iArr3, PExtInv.length);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        if (Nat.inc(5, iArr, iArr2) != 0 || (iArr2[4] == -1 && Nat160.gte(iArr2, f700P))) {
            Nat.addWordTo(5, PInv, iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat160.fromBigInteger(bigInteger);
        if (fromBigInteger[4] == -1 && Nat160.gte(fromBigInteger, f700P)) {
            Nat160.subFrom(f700P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(5, iArr, 0, iArr2);
        } else {
            Nat.shiftDownBit(5, iArr2, Nat160.add(iArr, f700P, iArr2));
        }
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f700P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 5; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] createExt = Nat160.createExt();
        Nat160.mul(iArr, iArr2, createExt);
        reduce(createExt, iArr3);
    }

    public static void multiplyAddToExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if ((Nat160.mulAddTo(iArr, iArr2, iArr3) != 0 || (iArr3[9] == -1 && Nat.gte(10, iArr3, PExt))) && Nat.addTo(PExtInv.length, PExtInv, iArr3) != 0) {
            Nat.incAt(10, iArr3, PExtInv.length);
        }
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat160.sub(f700P, f700P, iArr2);
        } else {
            Nat160.sub(f700P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[20];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 5);
        } while (0 == Nat.lessThan(5, iArr, f700P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        long j = iArr[5] & f699M;
        long j2 = iArr[6] & f699M;
        long j3 = iArr[7] & f699M;
        long j4 = iArr[8] & f699M;
        long j5 = iArr[9] & f699M;
        long j6 = 0 + (iArr[0] & f699M) + j + (j << 31);
        iArr2[0] = (int) j6;
        long j7 = (j6 >>> 32) + (iArr[1] & f699M) + j2 + (j2 << 31);
        iArr2[1] = (int) j7;
        long j8 = (j7 >>> 32) + (iArr[2] & f699M) + j3 + (j3 << 31);
        iArr2[2] = (int) j8;
        long j9 = (j8 >>> 32) + (iArr[3] & f699M) + j4 + (j4 << 31);
        iArr2[3] = (int) j9;
        long j10 = (j9 >>> 32) + (iArr[4] & f699M) + j5 + (j5 << 31);
        iArr2[4] = (int) j10;
        reduce32((int) (j10 >>> 32), iArr2);
    }

    public static void reduce32(int i, int[] iArr) {
        if ((i == 0 || Nat160.mulWordsAdd(PInv, i, iArr, 0) == 0) && !(iArr[4] == -1 && Nat160.gte(iArr, f700P))) {
            return;
        }
        Nat.addWordTo(5, PInv, iArr);
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] createExt = Nat160.createExt();
        Nat160.square(iArr, createExt);
        reduce(createExt, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] createExt = Nat160.createExt();
        Nat160.square(iArr, createExt);
        reduce(createExt, iArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            Nat160.square(iArr2, createExt);
            reduce(createExt, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat160.sub(iArr, iArr2, iArr3) != 0) {
            Nat.subWordFrom(5, PInv, iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(10, iArr, iArr2, iArr3) == 0 || Nat.subFrom(PExtInv.length, PExtInv, iArr3) == 0) {
            return;
        }
        Nat.decAt(10, iArr3, PExtInv.length);
    }

    public static void twice(int[] iArr, int[] iArr2) {
        if (Nat.shiftUpBit(5, iArr, 0, iArr2) != 0 || (iArr2[4] == -1 && Nat160.gte(iArr2, f700P))) {
            Nat.addWordTo(5, PInv, iArr2);
        }
    }
}