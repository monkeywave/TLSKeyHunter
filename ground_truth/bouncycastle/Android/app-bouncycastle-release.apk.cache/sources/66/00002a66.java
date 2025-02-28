package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
class GF2Field {
    public static final int MASK = 255;
    static final byte[][] gfMulTable = (byte[][]) Array.newInstance(Byte.TYPE, 256, 256);
    static final byte[] gfInvTable = new byte[256];

    static {
        long j;
        int i = 1;
        long j2 = 72340172838076673L;
        while (true) {
            j = 506097522914230528L;
            if (i > 255) {
                break;
            }
            for (int i2 = 0; i2 < 256; i2 += 8) {
                Pack.longToLittleEndian(gf256Mul_64(j2, j), gfMulTable[i], i2);
                j += 578721382704613384L;
            }
            j2 += 72340172838076673L;
            i++;
        }
        for (int i3 = 0; i3 < 256; i3 += 8) {
            Pack.longToLittleEndian(gf256Inv_64(j), gfInvTable, i3);
            j += 578721382704613384L;
        }
    }

    GF2Field() {
    }

    public static short addElem(short s, short s2) {
        return (short) (s ^ s2);
    }

    public static long addElem_64(long j, long j2) {
        return j ^ j2;
    }

    private static short gf16Mul(short s, short s2) {
        short s3 = (short) (s & 3);
        short s4 = (short) ((s >>> 2) & 255);
        short s5 = (short) (s2 & 3);
        short s6 = (short) ((s2 >>> 2) & 255);
        short gf4Mul = gf4Mul(s3, s5);
        short gf4Mul2 = gf4Mul(s4, s6);
        return (short) ((((((short) (gf4Mul((short) (s4 ^ s3), (short) (s6 ^ s5)) ^ gf4Mul)) << 2) ^ gf4Mul) ^ gf4Mul2(gf4Mul2)) & 255);
    }

    private static short gf16Mul8(short s) {
        short s2 = (short) ((s >>> 2) & 255);
        return (short) ((gf4Mul3(s2) | (gf4Mul2((short) (((short) (s & 3)) ^ s2)) << 2)) & 255);
    }

    private static long gf16Mul8_64(long j) {
        long j2 = 3689348814741910323L & j;
        long j3 = j & (-3689348814741910324L);
        long j4 = (j2 << 2) ^ j3;
        long j5 = j3 >>> 2;
        return j5 ^ gf4Mul2_64(j4 ^ j5);
    }

    private static long gf16Mul_64(long j, long j2) {
        long gf4Mul_64 = gf4Mul_64(j, j2);
        long j3 = 3689348814741910323L & gf4Mul_64;
        return (gf4Mul_64(((j ^ (j << 2)) & (-3689348814741910324L)) ^ ((gf4Mul_64 & (-3689348814741910324L)) >>> 2), ((j2 ^ (j2 << 2)) & (-3689348814741910324L)) ^ 2459565876494606882L) ^ (j3 << 2)) ^ j3;
    }

    private static short gf16Squ(short s) {
        short gf4Squ = gf4Squ((short) ((s >>> 2) & 255));
        return (short) ((((gf4Squ << 2) ^ gf4Mul2(gf4Squ)) ^ gf4Squ((short) (s & 3))) & 255);
    }

    private static long gf16Squ_64(long j) {
        long gf4Squ_64 = gf4Squ_64(j);
        return gf4Squ_64 ^ (gf4Mul2_64((-3689348814741910324L) & gf4Squ_64) >>> 2);
    }

    private static short gf256Inv(short s) {
        short gf256Squ = gf256Squ(s);
        short gf256Squ2 = gf256Squ(gf256Squ);
        short gf256Mul = gf256Mul(gf256Mul(gf256Squ2, gf256Squ), gf256Squ(gf256Squ2));
        return gf256Mul(gf256Squ, gf256Squ(gf256Mul(gf256Squ(gf256Squ(gf256Squ(gf256Mul))), gf256Mul)));
    }

    private static long gf256Inv_64(long j) {
        long gf256Squ_64 = gf256Squ_64(j);
        long gf256Squ_642 = gf256Squ_64(gf256Squ_64);
        long gf256Mul_64 = gf256Mul_64(gf256Mul_64(gf256Squ_642, gf256Squ_64), gf256Squ_64(gf256Squ_642));
        return gf256Mul_64(gf256Squ_64, gf256Squ_64(gf256Mul_64(gf256Squ_64(gf256Squ_64(gf256Squ_64(gf256Mul_64))), gf256Mul_64)));
    }

    private static short gf256Mul(short s, short s2) {
        short s3 = (short) (s & 15);
        short s4 = (short) ((s >>> 4) & 255);
        short s5 = (short) (s2 & 15);
        short s6 = (short) ((s2 >>> 4) & 255);
        short gf16Mul = gf16Mul(s3, s5);
        short gf16Mul2 = gf16Mul(s4, s6);
        return (short) ((((((short) (gf16Mul((short) (s4 ^ s3), (short) (s6 ^ s5)) ^ gf16Mul)) << 4) ^ gf16Mul) ^ gf16Mul8(gf16Mul2)) & 255);
    }

    private static long gf256Mul_64(long j, long j2) {
        long gf16Mul_64 = gf16Mul_64(j, j2);
        long j3 = 1085102592571150095L & gf16Mul_64;
        return (gf16Mul_64(((j ^ (j << 4)) & (-1085102592571150096L)) ^ ((gf16Mul_64 & (-1085102592571150096L)) >>> 4), ((j2 ^ (j2 << 4)) & (-1085102592571150096L)) ^ 578721382704613384L) ^ (j3 << 4)) ^ j3;
    }

    private static short gf256Squ(short s) {
        short gf16Squ = gf16Squ((short) ((s >>> 4) & 255));
        return (short) ((((gf16Squ << 4) ^ gf16Mul8(gf16Squ)) ^ gf16Squ((short) (s & 15))) & 255);
    }

    private static long gf256Squ_64(long j) {
        long gf16Squ_64 = gf16Squ_64(j);
        return gf16Squ_64 ^ (gf16Mul8_64((-1085102592571150096L) & gf16Squ_64) >>> 4);
    }

    private static short gf4Mul(short s, short s2) {
        return (short) (((gf4Mul2(s) * (s2 >>> 1)) ^ ((s2 & 1) * s)) & 255);
    }

    private static short gf4Mul2(short s) {
        return (short) ((((s >>> 1) * 7) ^ (s << 1)) & 255);
    }

    private static long gf4Mul2_64(long j) {
        long j2 = 6148914691236517205L & j;
        long j3 = j & (-6148914691236517206L);
        return (j3 >>> 1) ^ ((j2 << 1) ^ j3);
    }

    private static short gf4Mul3(short s) {
        int i = (s - 2) >>> 1;
        return (short) ((((s - 1) & (~i)) | ((s * 3) & i)) & 255);
    }

    private static long gf4Mul_64(long j, long j2) {
        long j3 = j & j2;
        return ((j3 & (-6148914691236517206L)) >>> 1) ^ (j3 ^ ((((j << 1) & j2) ^ ((j2 << 1) & j)) & (-6148914691236517206L)));
    }

    private static short gf4Squ(short s) {
        return (short) ((s ^ (s >>> 1)) & 255);
    }

    private static long gf4Squ_64(long j) {
        return j ^ (((-6148914691236517206L) & j) >>> 1);
    }

    public static short invElem(short s) {
        return (short) (gfInvTable[s] & UByte.MAX_VALUE);
    }

    public static long invElem_64(long j) {
        return gf256Inv_64(j);
    }

    public static short multElem(short s, short s2) {
        return (short) (gfMulTable[s][s2] & UByte.MAX_VALUE);
    }

    public static long multElem_64(long j, long j2) {
        return gf256Mul_64(j, j2);
    }
}