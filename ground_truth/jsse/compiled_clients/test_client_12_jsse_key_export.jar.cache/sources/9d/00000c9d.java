package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.raw.Mod;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat512;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP521R1Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP521R1Field.class */
public class SecP521R1Field {
    private static final int P16 = 511;

    /* renamed from: P */
    static final int[] f748P = {-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, P16};

    public static void add(int[] iArr, int[] iArr2, int[] iArr3) {
        int add = Nat.add(16, iArr, iArr2, iArr3) + iArr[16] + iArr2[16];
        if (add > P16 || (add == P16 && Nat.m19eq(16, iArr3, f748P))) {
            add = (add + Nat.inc(16, iArr3)) & P16;
        }
        iArr3[16] = add;
    }

    public static void addOne(int[] iArr, int[] iArr2) {
        int inc = Nat.inc(16, iArr, iArr2) + iArr[16];
        if (inc > P16 || (inc == P16 && Nat.m19eq(16, iArr2, f748P))) {
            inc = (inc + Nat.inc(16, iArr2)) & P16;
        }
        iArr2[16] = inc;
    }

    public static int[] fromBigInteger(BigInteger bigInteger) {
        int[] fromBigInteger = Nat.fromBigInteger(521, bigInteger);
        if (Nat.m19eq(17, fromBigInteger, f748P)) {
            Nat.zero(17, fromBigInteger);
        }
        return fromBigInteger;
    }

    public static void half(int[] iArr, int[] iArr2) {
        int i = iArr[16];
        iArr2[16] = (i >>> 1) | (Nat.shiftDownBit(16, iArr, i, iArr2) >>> 23);
    }

    public static void inv(int[] iArr, int[] iArr2) {
        Mod.checkedModOddInverse(f748P, iArr, iArr2);
    }

    public static int isZero(int[] iArr) {
        int i = 0;
        for (int i2 = 0; i2 < 17; i2++) {
            i |= iArr[i2];
        }
        return (((i >>> 1) | (i & 1)) - 1) >> 31;
    }

    public static void multiply(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] create = Nat.create(33);
        implMultiply(iArr, iArr2, create);
        reduce(create, iArr3);
    }

    public static void negate(int[] iArr, int[] iArr2) {
        if (0 != isZero(iArr)) {
            Nat.sub(17, f748P, f748P, iArr2);
        } else {
            Nat.sub(17, f748P, iArr, iArr2);
        }
    }

    public static void random(SecureRandom secureRandom, int[] iArr) {
        byte[] bArr = new byte[68];
        do {
            secureRandom.nextBytes(bArr);
            Pack.littleEndianToInt(bArr, 0, iArr, 0, 17);
            iArr[16] = iArr[16] & P16;
        } while (0 == Nat.lessThan(17, iArr, f748P));
    }

    public static void randomMult(SecureRandom secureRandom, int[] iArr) {
        do {
            random(secureRandom, iArr);
        } while (0 != isZero(iArr));
    }

    public static void reduce(int[] iArr, int[] iArr2) {
        int i = iArr[32];
        int shiftDownBits = (Nat.shiftDownBits(16, iArr, 16, 9, i, iArr2, 0) >>> 23) + (i >>> 9) + Nat.addTo(16, iArr, iArr2);
        if (shiftDownBits > P16 || (shiftDownBits == P16 && Nat.m19eq(16, iArr2, f748P))) {
            shiftDownBits = (shiftDownBits + Nat.inc(16, iArr2)) & P16;
        }
        iArr2[16] = shiftDownBits;
    }

    public static void reduce23(int[] iArr) {
        int i = iArr[16];
        int addWordTo = Nat.addWordTo(16, i >>> 9, iArr) + (i & P16);
        if (addWordTo > P16 || (addWordTo == P16 && Nat.m19eq(16, iArr, f748P))) {
            addWordTo = (addWordTo + Nat.inc(16, iArr)) & P16;
        }
        iArr[16] = addWordTo;
    }

    public static void square(int[] iArr, int[] iArr2) {
        int[] create = Nat.create(33);
        implSquare(iArr, create);
        reduce(create, iArr2);
    }

    public static void squareN(int[] iArr, int i, int[] iArr2) {
        int[] create = Nat.create(33);
        implSquare(iArr, create);
        reduce(create, iArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            implSquare(iArr2, create);
            reduce(create, iArr2);
        }
    }

    public static void subtract(int[] iArr, int[] iArr2, int[] iArr3) {
        int sub = (Nat.sub(16, iArr, iArr2, iArr3) + iArr[16]) - iArr2[16];
        if (sub < 0) {
            sub = (sub + Nat.dec(16, iArr3)) & P16;
        }
        iArr3[16] = sub;
    }

    public static void twice(int[] iArr, int[] iArr2) {
        int i = iArr[16];
        iArr2[16] = (Nat.shiftUpBit(16, iArr, i << 23, iArr2) | (i << 1)) & P16;
    }

    protected static void implMultiply(int[] iArr, int[] iArr2, int[] iArr3) {
        Nat512.mul(iArr, iArr2, iArr3);
        int i = iArr[16];
        int i2 = iArr2[16];
        iArr3[32] = Nat.mul31BothAdd(16, i, iArr2, i2, iArr, iArr3, 16) + (i * i2);
    }

    protected static void implSquare(int[] iArr, int[] iArr2) {
        Nat512.square(iArr, iArr2);
        int i = iArr[16];
        iArr2[32] = Nat.mulWordAddTo(16, i << 1, iArr, 0, iArr2, 16) + (i * i);
    }
}