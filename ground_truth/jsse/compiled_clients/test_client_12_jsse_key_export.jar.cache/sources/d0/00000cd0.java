package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import javassist.bytecode.Opcode;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat320;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT283Field */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT283Field.class */
public class SecT283Field {
    private static final long M27 = 134217727;
    private static final long M57 = 144115188075855871L;
    private static final long[] ROOT_Z = {878416384462358536L, 3513665537849438403L, -9076969306111048948L, 585610922974906400L, 34087042};

    public static void add(long[] jArr, long[] jArr2, long[] jArr3) {
        jArr3[0] = jArr[0] ^ jArr2[0];
        jArr3[1] = jArr[1] ^ jArr2[1];
        jArr3[2] = jArr[2] ^ jArr2[2];
        jArr3[3] = jArr[3] ^ jArr2[3];
        jArr3[4] = jArr[4] ^ jArr2[4];
    }

    public static void addExt(long[] jArr, long[] jArr2, long[] jArr3) {
        jArr3[0] = jArr[0] ^ jArr2[0];
        jArr3[1] = jArr[1] ^ jArr2[1];
        jArr3[2] = jArr[2] ^ jArr2[2];
        jArr3[3] = jArr[3] ^ jArr2[3];
        jArr3[4] = jArr[4] ^ jArr2[4];
        jArr3[5] = jArr[5] ^ jArr2[5];
        jArr3[6] = jArr[6] ^ jArr2[6];
        jArr3[7] = jArr[7] ^ jArr2[7];
        jArr3[8] = jArr[8] ^ jArr2[8];
    }

    public static void addOne(long[] jArr, long[] jArr2) {
        jArr2[0] = jArr[0] ^ 1;
        jArr2[1] = jArr[1];
        jArr2[2] = jArr[2];
        jArr2[3] = jArr[3];
        jArr2[4] = jArr[4];
    }

    private static void addTo(long[] jArr, long[] jArr2) {
        jArr2[0] = jArr2[0] ^ jArr[0];
        jArr2[1] = jArr2[1] ^ jArr[1];
        jArr2[2] = jArr2[2] ^ jArr[2];
        jArr2[3] = jArr2[3] ^ jArr[3];
        jArr2[4] = jArr2[4] ^ jArr[4];
    }

    public static long[] fromBigInteger(BigInteger bigInteger) {
        return Nat.fromBigInteger64(283, bigInteger);
    }

    public static void halfTrace(long[] jArr, long[] jArr2) {
        long[] create64 = Nat.create64(9);
        Nat320.copy64(jArr, jArr2);
        for (int i = 1; i < 283; i += 2) {
            implSquare(jArr2, create64);
            reduce(create64, jArr2);
            implSquare(jArr2, create64);
            reduce(create64, jArr2);
            addTo(jArr, jArr2);
        }
    }

    public static void invert(long[] jArr, long[] jArr2) {
        if (Nat320.isZero64(jArr)) {
            throw new IllegalStateException();
        }
        long[] create64 = Nat320.create64();
        long[] create642 = Nat320.create64();
        square(jArr, create64);
        multiply(create64, jArr, create64);
        squareN(create64, 2, create642);
        multiply(create642, create64, create642);
        squareN(create642, 4, create64);
        multiply(create64, create642, create64);
        squareN(create64, 8, create642);
        multiply(create642, create64, create642);
        square(create642, create642);
        multiply(create642, jArr, create642);
        squareN(create642, 17, create64);
        multiply(create64, create642, create64);
        square(create64, create64);
        multiply(create64, jArr, create64);
        squareN(create64, 35, create642);
        multiply(create642, create64, create642);
        squareN(create642, 70, create64);
        multiply(create64, create642, create64);
        square(create64, create64);
        multiply(create64, jArr, create64);
        squareN(create64, Opcode.F2D, create642);
        multiply(create642, create64, create642);
        square(create642, jArr2);
    }

    public static void multiply(long[] jArr, long[] jArr2, long[] jArr3) {
        long[] createExt64 = Nat320.createExt64();
        implMultiply(jArr, jArr2, createExt64);
        reduce(createExt64, jArr3);
    }

    public static void multiplyAddToExt(long[] jArr, long[] jArr2, long[] jArr3) {
        long[] createExt64 = Nat320.createExt64();
        implMultiply(jArr, jArr2, createExt64);
        addExt(jArr3, createExt64, jArr3);
    }

    public static void reduce(long[] jArr, long[] jArr2) {
        long j = jArr[0];
        long j2 = jArr[1];
        long j3 = jArr[2];
        long j4 = jArr[3];
        long j5 = jArr[4];
        long j6 = jArr[5];
        long j7 = jArr[6];
        long j8 = jArr[7];
        long j9 = jArr[8];
        long j10 = j4 ^ ((((j9 << 37) ^ (j9 << 42)) ^ (j9 << 44)) ^ (j9 << 49));
        long j11 = j5 ^ ((((j9 >>> 27) ^ (j9 >>> 22)) ^ (j9 >>> 20)) ^ (j9 >>> 15));
        long j12 = j3 ^ ((((j8 << 37) ^ (j8 << 42)) ^ (j8 << 44)) ^ (j8 << 49));
        long j13 = j10 ^ ((((j8 >>> 27) ^ (j8 >>> 22)) ^ (j8 >>> 20)) ^ (j8 >>> 15));
        long j14 = j2 ^ ((((j7 << 37) ^ (j7 << 42)) ^ (j7 << 44)) ^ (j7 << 49));
        long j15 = j12 ^ ((((j7 >>> 27) ^ (j7 >>> 22)) ^ (j7 >>> 20)) ^ (j7 >>> 15));
        long j16 = j ^ ((((j6 << 37) ^ (j6 << 42)) ^ (j6 << 44)) ^ (j6 << 49));
        long j17 = j14 ^ ((((j6 >>> 27) ^ (j6 >>> 22)) ^ (j6 >>> 20)) ^ (j6 >>> 15));
        long j18 = j11 >>> 27;
        jArr2[0] = (((j16 ^ j18) ^ (j18 << 5)) ^ (j18 << 7)) ^ (j18 << 12);
        jArr2[1] = j17;
        jArr2[2] = j15;
        jArr2[3] = j13;
        jArr2[4] = j11 & M27;
    }

    public static void reduce37(long[] jArr, int i) {
        long j = jArr[i + 4];
        long j2 = j >>> 27;
        jArr[i] = jArr[i] ^ (((j2 ^ (j2 << 5)) ^ (j2 << 7)) ^ (j2 << 12));
        jArr[i + 4] = j & M27;
    }

    public static void sqrt(long[] jArr, long[] jArr2) {
        long[] create64 = Nat320.create64();
        long unshuffle = Interleave.unshuffle(jArr[0]);
        long unshuffle2 = Interleave.unshuffle(jArr[1]);
        long j = (unshuffle & 4294967295L) | (unshuffle2 << 32);
        create64[0] = (unshuffle >>> 32) | (unshuffle2 & (-4294967296L));
        long unshuffle3 = Interleave.unshuffle(jArr[2]);
        long unshuffle4 = Interleave.unshuffle(jArr[3]);
        long j2 = (unshuffle3 & 4294967295L) | (unshuffle4 << 32);
        create64[1] = (unshuffle3 >>> 32) | (unshuffle4 & (-4294967296L));
        long unshuffle5 = Interleave.unshuffle(jArr[4]);
        create64[2] = unshuffle5 >>> 32;
        multiply(create64, ROOT_Z, jArr2);
        jArr2[0] = jArr2[0] ^ j;
        jArr2[1] = jArr2[1] ^ j2;
        jArr2[2] = jArr2[2] ^ (unshuffle5 & 4294967295L);
    }

    public static void square(long[] jArr, long[] jArr2) {
        long[] create64 = Nat.create64(9);
        implSquare(jArr, create64);
        reduce(create64, jArr2);
    }

    public static void squareAddToExt(long[] jArr, long[] jArr2) {
        long[] create64 = Nat.create64(9);
        implSquare(jArr, create64);
        addExt(jArr2, create64, jArr2);
    }

    public static void squareN(long[] jArr, int i, long[] jArr2) {
        long[] create64 = Nat.create64(9);
        implSquare(jArr, create64);
        reduce(create64, jArr2);
        while (true) {
            i--;
            if (i <= 0) {
                return;
            }
            implSquare(jArr2, create64);
            reduce(create64, jArr2);
        }
    }

    public static int trace(long[] jArr) {
        return ((int) (jArr[0] ^ (jArr[4] >>> 15))) & 1;
    }

    protected static void implCompactExt(long[] jArr) {
        long j = jArr[0];
        long j2 = jArr[1];
        long j3 = jArr[2];
        long j4 = jArr[3];
        long j5 = jArr[4];
        long j6 = jArr[5];
        long j7 = jArr[6];
        long j8 = jArr[7];
        long j9 = jArr[8];
        long j10 = jArr[9];
        jArr[0] = j ^ (j2 << 57);
        jArr[1] = (j2 >>> 7) ^ (j3 << 50);
        jArr[2] = (j3 >>> 14) ^ (j4 << 43);
        jArr[3] = (j4 >>> 21) ^ (j5 << 36);
        jArr[4] = (j5 >>> 28) ^ (j6 << 29);
        jArr[5] = (j6 >>> 35) ^ (j7 << 22);
        jArr[6] = (j7 >>> 42) ^ (j8 << 15);
        jArr[7] = (j8 >>> 49) ^ (j9 << 8);
        jArr[8] = (j9 >>> 56) ^ (j10 << 1);
        jArr[9] = j10 >>> 63;
    }

    protected static void implExpand(long[] jArr, long[] jArr2) {
        long j = jArr[0];
        long j2 = jArr[1];
        long j3 = jArr[2];
        long j4 = jArr[3];
        long j5 = jArr[4];
        jArr2[0] = j & M57;
        jArr2[1] = ((j >>> 57) ^ (j2 << 7)) & M57;
        jArr2[2] = ((j2 >>> 50) ^ (j3 << 14)) & M57;
        jArr2[3] = ((j3 >>> 43) ^ (j4 << 21)) & M57;
        jArr2[4] = (j4 >>> 36) ^ (j5 << 28);
    }

    protected static void implMultiply(long[] jArr, long[] jArr2, long[] jArr3) {
        long[] jArr4 = new long[5];
        long[] jArr5 = new long[5];
        implExpand(jArr, jArr4);
        implExpand(jArr2, jArr5);
        long[] jArr6 = new long[26];
        implMulw(jArr3, jArr4[0], jArr5[0], jArr6, 0);
        implMulw(jArr3, jArr4[1], jArr5[1], jArr6, 2);
        implMulw(jArr3, jArr4[2], jArr5[2], jArr6, 4);
        implMulw(jArr3, jArr4[3], jArr5[3], jArr6, 6);
        implMulw(jArr3, jArr4[4], jArr5[4], jArr6, 8);
        long j = jArr4[0] ^ jArr4[1];
        long j2 = jArr5[0] ^ jArr5[1];
        long j3 = jArr4[0] ^ jArr4[2];
        long j4 = jArr5[0] ^ jArr5[2];
        long j5 = jArr4[2] ^ jArr4[4];
        long j6 = jArr5[2] ^ jArr5[4];
        long j7 = jArr4[3] ^ jArr4[4];
        long j8 = jArr5[3] ^ jArr5[4];
        implMulw(jArr3, j3 ^ jArr4[3], j4 ^ jArr5[3], jArr6, 18);
        implMulw(jArr3, j5 ^ jArr4[1], j6 ^ jArr5[1], jArr6, 20);
        long j9 = j ^ j7;
        long j10 = j2 ^ j8;
        implMulw(jArr3, j9, j10, jArr6, 22);
        implMulw(jArr3, j9 ^ jArr4[2], j10 ^ jArr5[2], jArr6, 24);
        implMulw(jArr3, j, j2, jArr6, 10);
        implMulw(jArr3, j3, j4, jArr6, 12);
        implMulw(jArr3, j5, j6, jArr6, 14);
        implMulw(jArr3, j7, j8, jArr6, 16);
        jArr3[0] = jArr6[0];
        jArr3[9] = jArr6[9];
        long j11 = jArr6[0] ^ jArr6[1];
        long j12 = j11 ^ jArr6[2];
        long j13 = j12 ^ jArr6[10];
        jArr3[1] = j13;
        long j14 = jArr6[3] ^ jArr6[4];
        long j15 = j12 ^ (j14 ^ (jArr6[11] ^ jArr6[12]));
        jArr3[2] = j15;
        long j16 = j11 ^ j14;
        long j17 = jArr6[5] ^ jArr6[6];
        long j18 = (j16 ^ j17) ^ jArr6[8];
        long j19 = jArr6[13] ^ jArr6[14];
        jArr3[3] = (j18 ^ j19) ^ ((jArr6[18] ^ jArr6[22]) ^ jArr6[24]);
        long j20 = (jArr6[7] ^ jArr6[8]) ^ jArr6[9];
        long j21 = j20 ^ jArr6[17];
        jArr3[8] = j21;
        long j22 = (j20 ^ j17) ^ (jArr6[15] ^ jArr6[16]);
        jArr3[7] = j22;
        long j23 = j22 ^ j13;
        long j24 = jArr6[19] ^ jArr6[20];
        long j25 = jArr6[25] ^ jArr6[24];
        long j26 = jArr6[18] ^ jArr6[23];
        long j27 = j24 ^ j25;
        jArr3[4] = (j27 ^ j26) ^ j23;
        jArr3[5] = (j27 ^ (j15 ^ j21)) ^ (jArr6[21] ^ jArr6[22]);
        jArr3[6] = (((((j18 ^ jArr6[0]) ^ jArr6[9]) ^ j19) ^ jArr6[21]) ^ jArr6[23]) ^ jArr6[25];
        implCompactExt(jArr3);
    }

    protected static void implMulw(long[] jArr, long j, long j2, long[] jArr2, int i) {
        jArr[1] = j2;
        jArr[2] = jArr[1] << 1;
        jArr[3] = jArr[2] ^ j2;
        jArr[4] = jArr[2] << 1;
        jArr[5] = jArr[4] ^ j2;
        jArr[6] = jArr[3] << 1;
        jArr[7] = jArr[6] ^ j2;
        long j3 = 0;
        long j4 = jArr[((int) j) & 7];
        int i2 = 48;
        do {
            int i3 = (int) (j >>> i2);
            long j5 = (jArr[i3 & 7] ^ (jArr[(i3 >>> 3) & 7] << 3)) ^ (jArr[(i3 >>> 6) & 7] << 6);
            j4 ^= j5 << i2;
            j3 ^= j5 >>> (-i2);
            i2 -= 9;
        } while (i2 > 0);
        jArr2[i] = j4 & M57;
        jArr2[i + 1] = (j4 >>> 57) ^ ((j3 ^ (((j & 72198606942111744L) & ((j2 << 7) >> 63)) >>> 8)) << 7);
    }

    protected static void implSquare(long[] jArr, long[] jArr2) {
        Interleave.expand64To128(jArr, 0, 4, jArr2, 0);
        jArr2[8] = Interleave.expand32to64((int) jArr[4]);
    }
}