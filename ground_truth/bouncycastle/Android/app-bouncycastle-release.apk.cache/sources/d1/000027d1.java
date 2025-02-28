package org.bouncycastle.math.p016ec.rfc8032;

import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Scalar25519 */
/* loaded from: classes2.dex */
abstract class Scalar25519 {

    /* renamed from: L0 */
    private static final int f1132L0 = -50998291;

    /* renamed from: L1 */
    private static final int f1133L1 = 19280294;

    /* renamed from: L2 */
    private static final int f1134L2 = 127719000;

    /* renamed from: L3 */
    private static final int f1135L3 = -6428113;

    /* renamed from: L4 */
    private static final int f1136L4 = 5343;
    private static final long M08L = 255;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int SCALAR_BYTES = 32;
    static final int SIZE = 8;
    private static final int TARGET_LENGTH = 254;

    /* renamed from: L */
    private static final int[] f1131L = {1559614445, 1477600026, -1560830762, 350157278, 0, 0, 0, 268435456};
    private static final int[] LSq = {-1424848535, -487721339, 580428573, 1745064566, -770181698, 1036971123, 461123738, -1582065343, 1268693629, -889041821, -731974758, 43769659, 0, 0, 0, 16777216};

    Scalar25519() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean checkVar(byte[] bArr, int[] iArr) {
        decode(bArr, iArr);
        return !Nat256.gte(iArr, f1131L);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void decode(byte[] bArr, int[] iArr) {
        Codec.decode32(bArr, 0, iArr, 0, 8);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getOrderWnafVar(int i, byte[] bArr) {
        Wnaf.getSignedVar(f1131L, i, bArr);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void multiply128Var(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] iArr4 = new int[12];
        Nat256.mul128(iArr, iArr2, iArr4);
        if (iArr2[3] < 0) {
            Nat256.addTo(f1131L, 0, iArr4, 4, 0);
            Nat256.subFrom(iArr, 0, iArr4, 4, 0);
        }
        byte[] bArr = new byte[48];
        Codec.encode32(iArr4, 0, 12, bArr, 0);
        decode(reduce384(bArr), iArr3);
    }

    static byte[] reduce384(byte[] bArr) {
        long decode24 = Codec.decode24(bArr, 32) << 4;
        long j = decode24 & 4294967295L;
        long decode32 = Codec.decode32(bArr, 35);
        long j2 = decode32 & 4294967295L;
        long decode242 = Codec.decode24(bArr, 39) << 4;
        long j3 = decode242 & 4294967295L;
        long decode322 = Codec.decode32(bArr, 42);
        long decode16 = ((Codec.decode16(bArr, 46) << 4) & 4294967295L) + ((decode322 & 4294967295L) >> 28);
        long j4 = (decode322 & M28L) + (j3 >> 28);
        long decode323 = ((Codec.decode32(bArr, 14) & 4294967295L) - (decode16 * (-50998291))) - (j4 * 19280294);
        long decode243 = (((Codec.decode24(bArr, 18) << 4) & 4294967295L) - (decode16 * 19280294)) - (j4 * 127719000);
        long decode244 = (((Codec.decode24(bArr, 25) << 4) & 4294967295L) - (decode16 * (-6428113))) - (j4 * 5343);
        long j5 = (decode242 & M28L) + (j2 >> 28);
        long j6 = (decode32 & M28L) + (j >> 28);
        long j7 = decode24 & M28L;
        long decode245 = ((Codec.decode24(bArr, 4) << 4) & 4294967295L) - (j6 * (-50998291));
        long decode324 = ((Codec.decode32(bArr, 7) & 4294967295L) - (j5 * (-50998291))) - (j6 * 19280294);
        long decode246 = ((((Codec.decode24(bArr, 11) << 4) & 4294967295L) - (j4 * (-50998291))) - (j5 * 19280294)) - (j6 * 127719000);
        long j8 = (decode323 - (j5 * 127719000)) - (j6 * (-6428113));
        long j9 = (decode243 - (j5 * (-6428113))) - (j6 * 5343);
        long decode325 = ((Codec.decode32(bArr, 28) & 4294967295L) - (decode16 * 5343)) + (decode244 >> 28);
        long j10 = decode244 & M28L;
        long j11 = j7 + (decode325 >> 28);
        long j12 = decode325 & M28L;
        long j13 = j12 >>> 27;
        long j14 = j11 + j13;
        long decode326 = (Codec.decode32(bArr, 0) & 4294967295L) - (j14 * (-50998291));
        long j15 = (decode245 - (j14 * 19280294)) + (decode326 >> 28);
        long j16 = decode326 & M28L;
        long j17 = (decode324 - (j14 * 127719000)) + (j15 >> 28);
        long j18 = j15 & M28L;
        long j19 = (decode246 - (j14 * (-6428113))) + (j17 >> 28);
        long j20 = j17 & M28L;
        long j21 = (j8 - (j14 * 5343)) + (j19 >> 28);
        long j22 = j19 & M28L;
        long j23 = j9 + (j21 >> 28);
        long j24 = j21 & M28L;
        long decode327 = ((((Codec.decode32(bArr, 21) & 4294967295L) - (decode16 * 127719000)) - (j4 * (-6428113))) - (j5 * 5343)) + (j23 >> 28);
        long j25 = j23 & M28L;
        long j26 = j10 + (decode327 >> 28);
        long j27 = decode327 & M28L;
        long j28 = j12 + (j26 >> 28);
        long j29 = j26 & M28L;
        long j30 = j28 >> 28;
        long j31 = j28 & M28L;
        long j32 = j30 - j13;
        long j33 = j16 + (j32 & (-50998291));
        long j34 = j18 + (j32 & 19280294) + (j33 >> 28);
        long j35 = j33 & M28L;
        long j36 = j20 + (j32 & 127719000) + (j34 >> 28);
        long j37 = j34 & M28L;
        long j38 = j22 + (j32 & (-6428113)) + (j36 >> 28);
        long j39 = j36 & M28L;
        long j40 = j24 + (j32 & 5343) + (j38 >> 28);
        long j41 = j38 & M28L;
        long j42 = j25 + (j40 >> 28);
        long j43 = j40 & M28L;
        long j44 = j27 + (j42 >> 28);
        long j45 = j42 & M28L;
        long j46 = j29 + (j44 >> 28);
        long j47 = j44 & M28L;
        long j48 = j46 & M28L;
        byte[] bArr2 = new byte[64];
        Codec.encode56((j37 << 28) | j35, bArr2, 0);
        Codec.encode56(j39 | (j41 << 28), bArr2, 7);
        Codec.encode56((j45 << 28) | j43, bArr2, 14);
        Codec.encode56((j48 << 28) | j47, bArr2, 21);
        Codec.encode32((int) (j31 + (j46 >> 28)), bArr2, 28);
        return bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] reduce512(byte[] bArr) {
        long decode32 = Codec.decode32(bArr, 49);
        long j = decode32 & 4294967295L;
        long decode322 = Codec.decode32(bArr, 56);
        long j2 = decode322 & 4294967295L;
        long j3 = bArr[63] & M08L;
        long decode24 = ((Codec.decode24(bArr, 60) << 4) & 4294967295L) + (j2 >> 28);
        long j4 = decode322 & M28L;
        long decode323 = ((Codec.decode32(bArr, 42) & 4294967295L) - (j3 * (-6428113))) - (decode24 * 5343);
        long decode242 = ((((Codec.decode24(bArr, 39) << 4) & 4294967295L) - (j3 * 127719000)) - (decode24 * (-6428113))) - (j4 * 5343);
        long decode243 = ((Codec.decode24(bArr, 53) << 4) & 4294967295L) + (j >> 28);
        long j5 = decode32 & M28L;
        long decode324 = ((((Codec.decode32(bArr, 35) & 4294967295L) - (j3 * 19280294)) - (decode24 * 127719000)) - (j4 * (-6428113))) - (decode243 * 5343);
        long decode244 = ((((((Codec.decode24(bArr, 32) << 4) & 4294967295L) - (j3 * (-50998291))) - (decode24 * 19280294)) - (j4 * 127719000)) - (decode243 * (-6428113))) - (j5 * 5343);
        long decode245 = (((Codec.decode24(bArr, 46) << 4) & 4294967295L) - (j3 * 5343)) + (decode323 >> 28);
        long j6 = (decode323 & M28L) + (decode242 >> 28);
        long decode246 = ((((Codec.decode24(bArr, 18) << 4) & 4294967295L) - (j5 * (-50998291))) - (decode245 * 19280294)) - (j6 * 127719000);
        long decode247 = ((((((Codec.decode24(bArr, 25) << 4) & 4294967295L) - (j4 * (-50998291))) - (decode243 * 19280294)) - (j5 * 127719000)) - (decode245 * (-6428113))) - (j6 * 5343);
        long j7 = (decode242 & M28L) + (decode324 >> 28);
        long decode248 = (((Codec.decode24(bArr, 11) << 4) & 4294967295L) - (j6 * (-50998291))) - (j7 * 19280294);
        long decode325 = (((Codec.decode32(bArr, 14) & 4294967295L) - (decode245 * (-50998291))) - (j6 * 19280294)) - (j7 * 127719000);
        long decode326 = (((((Codec.decode32(bArr, 21) & 4294967295L) - (decode243 * (-50998291))) - (j5 * 19280294)) - (decode245 * 127719000)) - (j6 * (-6428113))) - (j7 * 5343);
        long j8 = (decode324 & M28L) + (decode244 >> 28);
        long j9 = decode244 & M28L;
        long decode249 = ((Codec.decode24(bArr, 4) << 4) & 4294967295L) - (j8 * (-50998291));
        long decode327 = ((Codec.decode32(bArr, 7) & 4294967295L) - (j7 * (-50998291))) - (j8 * 19280294);
        long j10 = decode248 - (j8 * 127719000);
        long j11 = decode325 - (j8 * (-6428113));
        long j12 = (decode246 - (j7 * (-6428113))) - (j8 * 5343);
        long decode328 = ((((((Codec.decode32(bArr, 28) & 4294967295L) - (decode24 * (-50998291))) - (j4 * 19280294)) - (decode243 * 127719000)) - (j5 * (-6428113))) - (decode245 * 5343)) + (decode247 >> 28);
        long j13 = decode247 & M28L;
        long j14 = decode328 & M28L;
        long j15 = j14 >>> 27;
        long j16 = j9 + (decode328 >> 28) + j15;
        long decode329 = (Codec.decode32(bArr, 0) & 4294967295L) - (j16 * (-50998291));
        long j17 = (decode249 - (j16 * 19280294)) + (decode329 >> 28);
        long j18 = decode329 & M28L;
        long j19 = (decode327 - (j16 * 127719000)) + (j17 >> 28);
        long j20 = j17 & M28L;
        long j21 = (j10 - (j16 * (-6428113))) + (j19 >> 28);
        long j22 = j19 & M28L;
        long j23 = (j11 - (j16 * 5343)) + (j21 >> 28);
        long j24 = j21 & M28L;
        long j25 = j12 + (j23 >> 28);
        long j26 = j23 & M28L;
        long j27 = decode326 + (j25 >> 28);
        long j28 = j25 & M28L;
        long j29 = j13 + (j27 >> 28);
        long j30 = j27 & M28L;
        long j31 = j14 + (j29 >> 28);
        long j32 = j29 & M28L;
        long j33 = j31 >> 28;
        long j34 = j31 & M28L;
        long j35 = j33 - j15;
        long j36 = j18 + (j35 & (-50998291));
        long j37 = j20 + (j35 & 19280294) + (j36 >> 28);
        long j38 = j36 & M28L;
        long j39 = j22 + (j35 & 127719000) + (j37 >> 28);
        long j40 = j37 & M28L;
        long j41 = j24 + (j35 & (-6428113)) + (j39 >> 28);
        long j42 = j39 & M28L;
        long j43 = j26 + (j35 & 5343) + (j41 >> 28);
        long j44 = j41 & M28L;
        long j45 = j28 + (j43 >> 28);
        long j46 = j43 & M28L;
        long j47 = j30 + (j45 >> 28);
        long j48 = j45 & M28L;
        long j49 = j32 + (j47 >> 28);
        long j50 = j47 & M28L;
        long j51 = j49 & M28L;
        byte[] bArr2 = new byte[32];
        Codec.encode56(j38 | (j40 << 28), bArr2, 0);
        Codec.encode56((j44 << 28) | j42, bArr2, 7);
        Codec.encode56(j46 | (j48 << 28), bArr2, 14);
        Codec.encode56(j50 | (j51 << 28), bArr2, 21);
        Codec.encode32((int) (j34 + (j49 >> 28)), bArr2, 28);
        return bArr2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean reduceBasisVar(int[] iArr, int[] iArr2, int[] iArr3) {
        int i;
        int i2;
        int[] iArr4;
        int[] iArr5 = new int[16];
        System.arraycopy(LSq, 0, iArr5, 0, 16);
        int[] iArr6 = new int[16];
        Nat256.square(iArr, iArr6);
        iArr6[0] = iArr6[0] + 1;
        int[] iArr7 = new int[16];
        int[] iArr8 = f1131L;
        Nat256.mul(iArr8, iArr, iArr7);
        int[] iArr9 = new int[16];
        int[] iArr10 = new int[4];
        System.arraycopy(iArr8, 0, iArr10, 0, 4);
        int[] iArr11 = new int[4];
        System.arraycopy(iArr, 0, iArr11, 0, 4);
        int[] iArr12 = new int[4];
        iArr12[0] = 1;
        int[] iArr13 = new int[4];
        int[] iArr14 = iArr10;
        int[] iArr15 = iArr11;
        int i3 = 15;
        int i4 = 1016;
        int bitLengthPositive = ScalarUtil.getBitLengthPositive(15, iArr6);
        while (bitLengthPositive > TARGET_LENGTH) {
            int i5 = i4 - 1;
            if (i5 < 0) {
                return false;
            }
            int bitLength = ScalarUtil.getBitLength(i3, iArr7) - bitLengthPositive;
            int i6 = bitLength & (~(bitLength >> 31));
            if (iArr7[i3] < 0) {
                i = bitLengthPositive;
                ScalarUtil.addShifted_NP(i3, i6, iArr5, iArr6, iArr7, iArr9);
                int[] iArr16 = iArr15;
                ScalarUtil.addShifted_UV(3, i6, iArr14, iArr13, iArr16, iArr12);
                iArr4 = iArr16;
                i2 = i3;
            } else {
                i = bitLengthPositive;
                ScalarUtil.subShifted_NP(i3, i6, iArr5, iArr6, iArr7, iArr9);
                i2 = i3;
                iArr4 = iArr15;
                ScalarUtil.subShifted_UV(3, i6, iArr14, iArr13, iArr4, iArr12);
            }
            if (ScalarUtil.lessThan(i2, iArr5, iArr6)) {
                int i7 = i >>> 5;
                i3 = i7;
                bitLengthPositive = ScalarUtil.getBitLengthPositive(i7, iArr5);
                iArr15 = iArr14;
                iArr14 = iArr4;
                int[] iArr17 = iArr13;
                iArr13 = iArr12;
                iArr12 = iArr17;
                int[] iArr18 = iArr6;
                iArr6 = iArr5;
                iArr5 = iArr18;
            } else {
                iArr15 = iArr4;
                i3 = i2;
                bitLengthPositive = i;
            }
            i4 = i5;
        }
        System.arraycopy(iArr15, 0, iArr2, 0, 4);
        System.arraycopy(iArr12, 0, iArr3, 0, 4);
        return true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void toSignedDigits(int i, int[] iArr) {
        Nat.caddTo(8, (~iArr[0]) & 1, f1131L, iArr);
        Nat.shiftDownBit(8, iArr, 1);
    }
}