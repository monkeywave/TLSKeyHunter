package org.bouncycastle.math.p010ec.custom.djb;

import java.math.BigInteger;
import java.security.SecureRandom;
import javassist.compiler.TokenId;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.djb.Curve25519Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/djb/Curve25519Field.class */
public class Curve25519Field {

    /* renamed from: M */
    private static final long f682M = 4294967295L;
    private static final int PInv = 19;

    /* renamed from: P7 */
    private static final int f684P7 = Integer.MAX_VALUE;

    /* renamed from: P */
    static final int[] f683P = {-19, -1, -1, -1, -1, -1, -1, f684P7};
    private static final int[] PExt = {TokenId.OR_E, 0, 0, 0, 0, 0, 0, 0, -19, -1, -1, -1, -1, -1, -1, 1073741823};

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        Nat256.add(iArr, iArr2, iArr3);
        if (Nat256.gte(iArr3, f683P)) {
            subPFrom(iArr3);
        }
    }

    public static void addExt(int[] iArr, int[] iArr2, int[] iArr3) {
        Nat.add(16, iArr, iArr2, iArr3);
        if (Nat.gte(16, iArr3, PExt)) {
            subPExtFrom(iArr3);
        }
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        Nat.inc(8, iArr, iArr2);
        if (Nat256.gte(iArr2, f683P)) {
            subPFrom(iArr2);
        }
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat256.fromBigInteger(bigInteger);
        while (Nat256.gte(fromBigInteger, f683P)) {
            Nat256.subFrom(f683P, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        if ((iArr[0] & 1) == 0) {
            Nat.shiftDownBit(8, iArr, 0, iArr2);
            return;
        }
        Nat256.add(iArr, f683P, iArr2);
        Nat.shiftDownBit(8, iArr2, 0);
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f683P, iArr, iArr2);
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
        Nat256.mulAddTo(iArr, iArr2, iArr3);
        if (Nat.gte(16, iArr3, PExt)) {
            subPExtFrom(iArr3);
        }
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat256.sub(f683P, f683P, iArr2);
        } else {
            Nat256.sub(f683P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[32];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 8);
            iArr[7] = iArr[7] & f684P7;
        } while (0 == Nat.lessThan(8, iArr, f683P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        int i = iArr[7];
        Nat.shiftUpBit(8, iArr, 8, i, iArr2, 0);
        int mulByWordAddTo = Nat256.mulByWordAddTo(19, iArr, iArr2) << 1;
        int i2 = iArr2[7];
        iArr2[7] = (i2 & f684P7) + Nat.addWordTo(7, (mulByWordAddTo + ((i2 >>> 31) - (i >>> 31))) * 19, iArr2);
        if (Nat256.gte(iArr2, f683P)) {
            subPFrom(iArr2);
        }
    }

    public static void reduce27(int i, int[] iArr) {
        int i2 = iArr[7];
        iArr[7] = (i2 & f684P7) + Nat.addWordTo(7, ((i << 1) | (i2 >>> 31)) * 19, iArr);
        if (Nat256.gte(iArr, f683P)) {
            subPFrom(iArr);
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
            i--;
            if (i <= 0) {
                return;
            }
            Nat256.square(iArr2, createExt);
            reduce(createExt, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat256.sub(iArr, iArr2, iArr3) != 0) {
            addPTo(iArr3);
        }
    }

    public static void subtractExt(int[] iArr, int[] iArr2, int[] iArr3) {
        if (Nat.sub(16, iArr, iArr2, iArr3) != 0) {
            addPExtTo(iArr3);
        }
    }

    public static void twice(int[] iArr, int[] iArr2) {
        Nat.shiftUpBit(8, iArr, 0, iArr2);
        if (Nat256.gte(iArr2, f683P)) {
            subPFrom(iArr2);
        }
    }

    private static int addPTo(int[] iArr) {
        long j = (iArr[0] & f682M) - 19;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            j2 = Nat.decAt(7, iArr, 1);
        }
        long j3 = j2 + (iArr[7] & f682M) + 2147483648L;
        iArr[7] = (int) j3;
        return (int) (j3 >> 32);
    }

    private static int addPExtTo(int[] iArr) {
        long j = (iArr[0] & f682M) + (PExt[0] & f682M);
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            j2 = Nat.incAt(8, iArr, 1);
        }
        long j3 = j2 + ((iArr[8] & f682M) - 19);
        iArr[8] = (int) j3;
        long j4 = j3 >> 32;
        if (j4 != 0) {
            j4 = Nat.decAt(15, iArr, 9);
        }
        long j5 = j4 + (iArr[15] & f682M) + ((PExt[15] + 1) & f682M);
        iArr[15] = (int) j5;
        return (int) (j5 >> 32);
    }

    private static int subPFrom(int[] iArr) {
        long j = (iArr[0] & f682M) + 19;
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            j2 = Nat.incAt(7, iArr, 1);
        }
        long j3 = j2 + ((iArr[7] & f682M) - 2147483648L);
        iArr[7] = (int) j3;
        return (int) (j3 >> 32);
    }

    private static int subPExtFrom(int[] iArr) {
        long j = (iArr[0] & f682M) - (PExt[0] & f682M);
        iArr[0] = (int) j;
        long j2 = j >> 32;
        if (j2 != 0) {
            j2 = Nat.decAt(8, iArr, 1);
        }
        long j3 = j2 + (iArr[8] & f682M) + 19;
        iArr[8] = (int) j3;
        long j4 = j3 >> 32;
        if (j4 != 0) {
            j4 = Nat.incAt(15, iArr, 9);
        }
        long j5 = j4 + ((iArr[15] & f682M) - ((PExt[15] + 1) & f682M));
        iArr[15] = (int) j5;
        return (int) (j5 >> 32);
    }
}