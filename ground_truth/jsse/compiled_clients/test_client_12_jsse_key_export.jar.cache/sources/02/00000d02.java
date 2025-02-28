package org.bouncycastle.math.p010ec.rfc8032;

import java.security.SecureRandom;
import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.p010ec.rfc7748.X448;
import org.bouncycastle.math.p010ec.rfc7748.X448Field;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448 */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed448.class */
public abstract class Ed448 {
    private static final long M26L = 67108863;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int COORD_INTS = 14;
    private static final int POINT_BYTES = 57;
    private static final int SCALAR_INTS = 14;
    private static final int SCALAR_BYTES = 57;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 57;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = 114;
    private static final int L_0 = 78101261;
    private static final int L_1 = 141809365;
    private static final int L_2 = 175155932;
    private static final int L_3 = 64542499;
    private static final int L_4 = 158326419;
    private static final int L_5 = 191173276;
    private static final int L_6 = 104575268;
    private static final int L_7 = 137584065;
    private static final int L4_0 = 43969588;
    private static final int L4_1 = 30366549;
    private static final int L4_2 = 163752818;
    private static final int L4_3 = 258169998;
    private static final int L4_4 = 96434764;
    private static final int L4_5 = 227822194;
    private static final int L4_6 = 149865618;
    private static final int L4_7 = 550336261;
    private static final int C_d = -39081;
    private static final int WNAF_WIDTH_BASE = 7;
    private static final int PRECOMP_BLOCKS = 5;
    private static final int PRECOMP_TEETH = 5;
    private static final int PRECOMP_SPACING = 18;
    private static final int PRECOMP_POINTS = 16;
    private static final int PRECOMP_MASK = 15;
    private static final byte[] DOM4_PREFIX = {83, 105, 103, 69, 100, 52, 52, 56};

    /* renamed from: P */
    private static final int[] f781P = {-1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1};

    /* renamed from: L */
    private static final int[] f782L = {-1420278541, 595116690, -1916432555, 560775794, -1361693040, -1001465015, 2093622249, -1, -1, -1, -1, -1, -1, 1073741823};
    private static final int[] B_x = {118276190, 40534716, 9670182, 135141552, 85017403, 259173222, 68333082, 171784774, 174973732, 15824510, 73756743, 57518561, 94773951, 248652241, 107736333, 82941708};
    private static final int[] B_y = {36764180, 8885695, 130592152, 20104429, 163904957, 30304195, 121295871, 5901357, 125344798, 171541512, 175338348, 209069246, 3626697, 38307682, 24032956, 110359655};
    private static final Object precompLock = new Object();
    private static PointExt[] precompBaseTable = null;
    private static int[] precompBase = null;

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$Algorithm */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed448$Algorithm.class */
    public static final class Algorithm {
        public static final int Ed448 = 0;
        public static final int Ed448ph = 1;
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$F */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed448$F.class */
    private static class C0324F extends X448Field {
        private C0324F() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PointExt */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed448$PointExt.class */
    public static class PointExt {

        /* renamed from: x */
        int[] f783x;

        /* renamed from: y */
        int[] f784y;

        /* renamed from: z */
        int[] f785z;

        private PointExt() {
            this.f783x = C0324F.create();
            this.f784y = C0324F.create();
            this.f785z = C0324F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PointPrecomp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed448$PointPrecomp.class */
    public static class PointPrecomp {

        /* renamed from: x */
        int[] f786x;

        /* renamed from: y */
        int[] f787y;

        private PointPrecomp() {
            this.f786x = C0324F.create();
            this.f787y = C0324F.create();
        }
    }

    private static byte[] calculateS(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int[] iArr = new int[28];
        decodeScalar(bArr, 0, iArr);
        int[] iArr2 = new int[14];
        decodeScalar(bArr2, 0, iArr2);
        int[] iArr3 = new int[14];
        decodeScalar(bArr3, 0, iArr3);
        Nat.mulAddTo(14, iArr2, iArr3, iArr);
        byte[] bArr4 = new byte[114];
        for (int i = 0; i < iArr.length; i++) {
            encode32(iArr[i], bArr4, i * 4);
        }
        return reduceScalar(bArr4);
    }

    private static boolean checkContextVar(byte[] bArr) {
        return bArr != null && bArr.length < 256;
    }

    private static int checkPoint(int[] iArr, int[] iArr2) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        C0324F.sqr(iArr, create2);
        C0324F.sqr(iArr2, create3);
        C0324F.mul(create2, create3, create);
        C0324F.add(create2, create3, create2);
        C0324F.mul(create, 39081, create);
        C0324F.subOne(create);
        C0324F.add(create, create2, create);
        C0324F.normalize(create);
        return C0324F.isZero(create);
    }

    private static int checkPoint(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        int[] create4 = C0324F.create();
        C0324F.sqr(iArr, create2);
        C0324F.sqr(iArr2, create3);
        C0324F.sqr(iArr3, create4);
        C0324F.mul(create2, create3, create);
        C0324F.add(create2, create3, create2);
        C0324F.mul(create2, create4, create2);
        C0324F.sqr(create4, create4);
        C0324F.mul(create, 39081, create);
        C0324F.sub(create, create4, create);
        C0324F.add(create, create2, create);
        C0324F.normalize(create);
        return C0324F.isZero(create);
    }

    private static boolean checkPointVar(byte[] bArr) {
        if ((bArr[56] & Byte.MAX_VALUE) != 0) {
            return false;
        }
        int[] iArr = new int[14];
        decode32(bArr, 0, iArr, 0, 14);
        return !Nat.gte(14, iArr, f781P);
    }

    private static boolean checkScalarVar(byte[] bArr, int[] iArr) {
        if (bArr[56] != 0) {
            return false;
        }
        decodeScalar(bArr, 0, iArr);
        return !Nat.gte(14, iArr, f782L);
    }

    private static byte[] copy(byte[] bArr, int i, int i2) {
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        return bArr2;
    }

    public static Xof createPrehash() {
        return createXof();
    }

    private static Xof createXof() {
        return new SHAKEDigest(256);
    }

    private static int decode16(byte[] bArr, int i) {
        return (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8);
    }

    private static int decode24(byte[] bArr, int i) {
        int i2 = i + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i2 + 1] & 255) << 16);
    }

    private static int decode32(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16) | (bArr[i3 + 1] << 24);
    }

    private static void decode32(byte[] bArr, int i, int[] iArr, int i2, int i3) {
        for (int i4 = 0; i4 < i3; i4++) {
            iArr[i2 + i4] = decode32(bArr, i + (i4 * 4));
        }
    }

    private static boolean decodePointVar(byte[] bArr, int i, boolean z, PointExt pointExt) {
        byte[] copy = copy(bArr, i, 57);
        if (checkPointVar(copy)) {
            int i2 = (copy[56] & 128) >>> 7;
            copy[56] = (byte) (copy[56] & Byte.MAX_VALUE);
            C0324F.decode(copy, 0, pointExt.f784y);
            int[] create = C0324F.create();
            int[] create2 = C0324F.create();
            C0324F.sqr(pointExt.f784y, create);
            C0324F.mul(create, 39081, create2);
            C0324F.negate(create, create);
            C0324F.addOne(create);
            C0324F.addOne(create2);
            if (C0324F.sqrtRatioVar(create, create2, pointExt.f783x)) {
                C0324F.normalize(pointExt.f783x);
                if (i2 == 1 && C0324F.isZeroVar(pointExt.f783x)) {
                    return false;
                }
                if (z ^ (i2 != (pointExt.f783x[0] & 1))) {
                    C0324F.negate(pointExt.f783x, pointExt.f783x);
                }
                pointExtendXY(pointExt);
                return true;
            }
            return false;
        }
        return false;
    }

    private static void decodeScalar(byte[] bArr, int i, int[] iArr) {
        decode32(bArr, i, iArr, 0, 14);
    }

    private static void dom4(Xof xof, byte b, byte[] bArr) {
        int length = DOM4_PREFIX.length;
        byte[] bArr2 = new byte[length + 2 + bArr.length];
        System.arraycopy(DOM4_PREFIX, 0, bArr2, 0, length);
        bArr2[length] = b;
        bArr2[length + 1] = (byte) bArr.length;
        System.arraycopy(bArr, 0, bArr2, length + 2, bArr.length);
        xof.update(bArr2, 0, bArr2.length);
    }

    private static void encode24(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        int i3 = i2 + 1;
        bArr[i3] = (byte) (i >>> 8);
        bArr[i3 + 1] = (byte) (i >>> 16);
    }

    private static void encode32(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        int i3 = i2 + 1;
        bArr[i3] = (byte) (i >>> 8);
        int i4 = i3 + 1;
        bArr[i4] = (byte) (i >>> 16);
        bArr[i4 + 1] = (byte) (i >>> 24);
    }

    private static void encode56(long j, byte[] bArr, int i) {
        encode32((int) j, bArr, i);
        encode24((int) (j >>> 32), bArr, i + 4);
    }

    private static int encodePoint(PointExt pointExt, byte[] bArr, int i) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        C0324F.inv(pointExt.f785z, create2);
        C0324F.mul(pointExt.f783x, create2, create);
        C0324F.mul(pointExt.f784y, create2, create2);
        C0324F.normalize(create);
        C0324F.normalize(create2);
        int checkPoint = checkPoint(create, create2);
        C0324F.encode(create2, bArr, i);
        bArr[(i + 57) - 1] = (byte) ((create[0] & 1) << 7);
        return checkPoint;
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        secureRandom.nextBytes(bArr);
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        Xof createXof = createXof();
        byte[] bArr3 = new byte[114];
        createXof.update(bArr, i, 57);
        createXof.doFinal(bArr3, 0, bArr3.length);
        byte[] bArr4 = new byte[57];
        pruneScalar(bArr3, 0, bArr4);
        scalarMultBaseEncoded(bArr4, bArr2, i2);
    }

    private static int getWindow4(int[] iArr, int i) {
        return (iArr[i >>> 3] >>> ((i & 7) << 2)) & 15;
    }

    private static byte[] getWnafVar(int[] iArr, int i) {
        int[] iArr2 = new int[28];
        int length = iArr2.length;
        int i2 = 0;
        int i3 = 14;
        while (true) {
            i3--;
            if (i3 < 0) {
                break;
            }
            int i4 = iArr[i3];
            int i5 = length - 1;
            iArr2[i5] = (i4 >>> 16) | (i2 << 16);
            length = i5 - 1;
            i2 = i4;
            iArr2[length] = i4;
        }
        byte[] bArr = new byte[447];
        int i6 = 32 - i;
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        while (i9 < iArr2.length) {
            int i10 = iArr2[i9];
            while (i7 < 16) {
                int i11 = i10 >>> i7;
                if ((i11 & 1) == i8) {
                    i7++;
                } else {
                    int i12 = (i11 | 1) << i6;
                    i8 = i12 >>> 31;
                    bArr[(i9 << 4) + i7] = (byte) (i12 >> i6);
                    i7 += i;
                }
            }
            i9++;
            i7 -= 16;
        }
        return bArr;
    }

    private static void implSign(Xof xof, byte[] bArr, byte[] bArr2, byte[] bArr3, int i, byte[] bArr4, byte b, byte[] bArr5, int i2, int i3, byte[] bArr6, int i4) {
        dom4(xof, b, bArr4);
        xof.update(bArr, 57, 57);
        xof.update(bArr5, i2, i3);
        xof.doFinal(bArr, 0, bArr.length);
        byte[] reduceScalar = reduceScalar(bArr);
        byte[] bArr7 = new byte[57];
        scalarMultBaseEncoded(reduceScalar, bArr7, 0);
        dom4(xof, b, bArr4);
        xof.update(bArr7, 0, 57);
        xof.update(bArr3, i, 57);
        xof.update(bArr5, i2, i3);
        xof.doFinal(bArr, 0, bArr.length);
        byte[] calculateS = calculateS(reduceScalar, reduceScalar(bArr), bArr2);
        System.arraycopy(bArr7, 0, bArr6, i4, 57);
        System.arraycopy(calculateS, 0, bArr6, i4 + 57, 57);
    }

    private static void implSign(byte[] bArr, int i, byte[] bArr2, byte b, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        if (!checkContextVar(bArr2)) {
            throw new IllegalArgumentException("ctx");
        }
        Xof createXof = createXof();
        byte[] bArr5 = new byte[114];
        createXof.update(bArr, i, 57);
        createXof.doFinal(bArr5, 0, bArr5.length);
        byte[] bArr6 = new byte[57];
        pruneScalar(bArr5, 0, bArr6);
        byte[] bArr7 = new byte[57];
        scalarMultBaseEncoded(bArr6, bArr7, 0);
        implSign(createXof, bArr5, bArr6, bArr7, 0, bArr2, b, bArr3, i2, i3, bArr4, i4);
    }

    private static void implSign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte b, byte[] bArr4, int i3, int i4, byte[] bArr5, int i5) {
        if (!checkContextVar(bArr3)) {
            throw new IllegalArgumentException("ctx");
        }
        Xof createXof = createXof();
        byte[] bArr6 = new byte[114];
        createXof.update(bArr, i, 57);
        createXof.doFinal(bArr6, 0, bArr6.length);
        byte[] bArr7 = new byte[57];
        pruneScalar(bArr6, 0, bArr7);
        implSign(createXof, bArr6, bArr7, bArr2, i2, bArr3, b, bArr4, i3, i4, bArr5, i5);
    }

    private static boolean implVerify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte b, byte[] bArr4, int i3, int i4) {
        if (checkContextVar(bArr3)) {
            byte[] copy = copy(bArr, i, 57);
            byte[] copy2 = copy(bArr, i + 57, 57);
            if (checkPointVar(copy)) {
                int[] iArr = new int[14];
                if (checkScalarVar(copy2, iArr)) {
                    PointExt pointExt = new PointExt();
                    if (decodePointVar(bArr2, i2, true, pointExt)) {
                        Xof createXof = createXof();
                        byte[] bArr5 = new byte[114];
                        dom4(createXof, b, bArr3);
                        createXof.update(copy, 0, 57);
                        createXof.update(bArr2, i2, 57);
                        createXof.update(bArr4, i3, i4);
                        createXof.doFinal(bArr5, 0, bArr5.length);
                        byte[] reduceScalar = reduceScalar(bArr5);
                        int[] iArr2 = new int[14];
                        decodeScalar(reduceScalar, 0, iArr2);
                        PointExt pointExt2 = new PointExt();
                        scalarMultStrausVar(iArr, iArr2, pointExt, pointExt2);
                        byte[] bArr6 = new byte[57];
                        return 0 != encodePoint(pointExt2, bArr6, 0) && Arrays.areEqual(bArr6, copy);
                    }
                    return false;
                }
                return false;
            }
            return false;
        }
        throw new IllegalArgumentException("ctx");
    }

    private static boolean isNeutralElementVar(int[] iArr, int[] iArr2, int[] iArr3) {
        return C0324F.isZeroVar(iArr) && C0324F.areEqualVar(iArr2, iArr3);
    }

    private static void pointAdd(PointExt pointExt, PointExt pointExt2) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        int[] create4 = C0324F.create();
        int[] create5 = C0324F.create();
        int[] create6 = C0324F.create();
        int[] create7 = C0324F.create();
        int[] create8 = C0324F.create();
        C0324F.mul(pointExt.f785z, pointExt2.f785z, create);
        C0324F.sqr(create, create2);
        C0324F.mul(pointExt.f783x, pointExt2.f783x, create3);
        C0324F.mul(pointExt.f784y, pointExt2.f784y, create4);
        C0324F.mul(create3, create4, create5);
        C0324F.mul(create5, 39081, create5);
        C0324F.add(create2, create5, create6);
        C0324F.sub(create2, create5, create7);
        C0324F.add(pointExt.f783x, pointExt.f784y, create2);
        C0324F.add(pointExt2.f783x, pointExt2.f784y, create5);
        C0324F.mul(create2, create5, create8);
        C0324F.add(create4, create3, create2);
        C0324F.sub(create4, create3, create5);
        C0324F.carry(create2);
        C0324F.sub(create8, create2, create8);
        C0324F.mul(create8, create, create8);
        C0324F.mul(create5, create, create5);
        C0324F.mul(create6, create8, pointExt2.f783x);
        C0324F.mul(create5, create7, pointExt2.f784y);
        C0324F.mul(create6, create7, pointExt2.f785z);
    }

    private static void pointAddVar(boolean z, PointExt pointExt, PointExt pointExt2) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        int[] create4 = C0324F.create();
        int[] create5 = C0324F.create();
        int[] create6 = C0324F.create();
        int[] create7 = C0324F.create();
        int[] create8 = C0324F.create();
        if (z) {
            iArr = create5;
            iArr2 = create2;
            iArr3 = create7;
            iArr4 = create6;
            C0324F.sub(pointExt.f784y, pointExt.f783x, create8);
        } else {
            iArr = create2;
            iArr2 = create5;
            iArr3 = create6;
            iArr4 = create7;
            C0324F.add(pointExt.f784y, pointExt.f783x, create8);
        }
        C0324F.mul(pointExt.f785z, pointExt2.f785z, create);
        C0324F.sqr(create, create2);
        C0324F.mul(pointExt.f783x, pointExt2.f783x, create3);
        C0324F.mul(pointExt.f784y, pointExt2.f784y, create4);
        C0324F.mul(create3, create4, create5);
        C0324F.mul(create5, 39081, create5);
        C0324F.add(create2, create5, iArr3);
        C0324F.sub(create2, create5, iArr4);
        C0324F.add(pointExt2.f783x, pointExt2.f784y, create5);
        C0324F.mul(create8, create5, create8);
        C0324F.add(create4, create3, iArr);
        C0324F.sub(create4, create3, iArr2);
        C0324F.carry(iArr);
        C0324F.sub(create8, create2, create8);
        C0324F.mul(create8, create, create8);
        C0324F.mul(create5, create, create5);
        C0324F.mul(create6, create8, pointExt2.f783x);
        C0324F.mul(create5, create7, pointExt2.f784y);
        C0324F.mul(create6, create7, pointExt2.f785z);
    }

    private static void pointAddPrecomp(PointPrecomp pointPrecomp, PointExt pointExt) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        int[] create4 = C0324F.create();
        int[] create5 = C0324F.create();
        int[] create6 = C0324F.create();
        int[] create7 = C0324F.create();
        C0324F.sqr(pointExt.f785z, create);
        C0324F.mul(pointPrecomp.f786x, pointExt.f783x, create2);
        C0324F.mul(pointPrecomp.f787y, pointExt.f784y, create3);
        C0324F.mul(create2, create3, create4);
        C0324F.mul(create4, 39081, create4);
        C0324F.add(create, create4, create5);
        C0324F.sub(create, create4, create6);
        C0324F.add(pointPrecomp.f786x, pointPrecomp.f787y, create);
        C0324F.add(pointExt.f783x, pointExt.f784y, create4);
        C0324F.mul(create, create4, create7);
        C0324F.add(create3, create2, create);
        C0324F.sub(create3, create2, create4);
        C0324F.carry(create);
        C0324F.sub(create7, create, create7);
        C0324F.mul(create7, pointExt.f785z, create7);
        C0324F.mul(create4, pointExt.f785z, create4);
        C0324F.mul(create5, create7, pointExt.f783x);
        C0324F.mul(create4, create6, pointExt.f784y);
        C0324F.mul(create5, create6, pointExt.f785z);
    }

    private static PointExt pointCopy(PointExt pointExt) {
        PointExt pointExt2 = new PointExt();
        pointCopy(pointExt, pointExt2);
        return pointExt2;
    }

    private static void pointCopy(PointExt pointExt, PointExt pointExt2) {
        C0324F.copy(pointExt.f783x, 0, pointExt2.f783x, 0);
        C0324F.copy(pointExt.f784y, 0, pointExt2.f784y, 0);
        C0324F.copy(pointExt.f785z, 0, pointExt2.f785z, 0);
    }

    private static void pointDouble(PointExt pointExt) {
        int[] create = C0324F.create();
        int[] create2 = C0324F.create();
        int[] create3 = C0324F.create();
        int[] create4 = C0324F.create();
        int[] create5 = C0324F.create();
        int[] create6 = C0324F.create();
        C0324F.add(pointExt.f783x, pointExt.f784y, create);
        C0324F.sqr(create, create);
        C0324F.sqr(pointExt.f783x, create2);
        C0324F.sqr(pointExt.f784y, create3);
        C0324F.add(create2, create3, create4);
        C0324F.carry(create4);
        C0324F.sqr(pointExt.f785z, create5);
        C0324F.add(create5, create5, create5);
        C0324F.carry(create5);
        C0324F.sub(create4, create5, create6);
        C0324F.sub(create, create4, create);
        C0324F.sub(create2, create3, create2);
        C0324F.mul(create, create6, pointExt.f783x);
        C0324F.mul(create4, create2, pointExt.f784y);
        C0324F.mul(create4, create6, pointExt.f785z);
    }

    private static void pointExtendXY(PointExt pointExt) {
        C0324F.one(pointExt.f785z);
    }

    private static void pointLookup(int i, int i2, PointPrecomp pointPrecomp) {
        int i3 = i * 16 * 2 * 16;
        for (int i4 = 0; i4 < 16; i4++) {
            int i5 = ((i4 ^ i2) - 1) >> 31;
            C0324F.cmov(i5, precompBase, i3, pointPrecomp.f786x, 0);
            int i6 = i3 + 16;
            C0324F.cmov(i5, precompBase, i6, pointPrecomp.f787y, 0);
            i3 = i6 + 16;
        }
    }

    private static void pointLookup(int[] iArr, int i, int[] iArr2, PointExt pointExt) {
        int window4 = getWindow4(iArr, i);
        int i2 = (window4 >>> 3) ^ 1;
        int i3 = (window4 ^ (-i2)) & 7;
        int i4 = 0;
        for (int i5 = 0; i5 < 8; i5++) {
            int i6 = ((i5 ^ i3) - 1) >> 31;
            C0324F.cmov(i6, iArr2, i4, pointExt.f783x, 0);
            int i7 = i4 + 16;
            C0324F.cmov(i6, iArr2, i7, pointExt.f784y, 0);
            int i8 = i7 + 16;
            C0324F.cmov(i6, iArr2, i8, pointExt.f785z, 0);
            i4 = i8 + 16;
        }
        C0324F.cnegate(i2, pointExt.f783x);
    }

    private static int[] pointPrecompute(PointExt pointExt, int i) {
        PointExt pointCopy = pointCopy(pointExt);
        PointExt pointCopy2 = pointCopy(pointCopy);
        pointDouble(pointCopy2);
        int[] createTable = C0324F.createTable(i * 3);
        int i2 = 0;
        int i3 = 0;
        while (true) {
            C0324F.copy(pointCopy.f783x, 0, createTable, i2);
            int i4 = i2 + 16;
            C0324F.copy(pointCopy.f784y, 0, createTable, i4);
            int i5 = i4 + 16;
            C0324F.copy(pointCopy.f785z, 0, createTable, i5);
            i2 = i5 + 16;
            i3++;
            if (i3 == i) {
                return createTable;
            }
            pointAdd(pointCopy2, pointCopy);
        }
    }

    private static PointExt[] pointPrecomputeVar(PointExt pointExt, int i) {
        PointExt pointCopy = pointCopy(pointExt);
        pointDouble(pointCopy);
        PointExt[] pointExtArr = new PointExt[i];
        pointExtArr[0] = pointCopy(pointExt);
        for (int i2 = 1; i2 < i; i2++) {
            pointExtArr[i2] = pointCopy(pointExtArr[i2 - 1]);
            pointAddVar(false, pointCopy, pointExtArr[i2]);
        }
        return pointExtArr;
    }

    private static void pointSetNeutral(PointExt pointExt) {
        C0324F.zero(pointExt.f783x);
        C0324F.one(pointExt.f784y);
        C0324F.one(pointExt.f785z);
    }

    public static void precompute() {
        synchronized (precompLock) {
            if (precompBase != null) {
                return;
            }
            PointExt pointExt = new PointExt();
            C0324F.copy(B_x, 0, pointExt.f783x, 0);
            C0324F.copy(B_y, 0, pointExt.f784y, 0);
            pointExtendXY(pointExt);
            precompBaseTable = pointPrecomputeVar(pointExt, 32);
            precompBase = C0324F.createTable(Opcode.IF_ICMPNE);
            int i = 0;
            for (int i2 = 0; i2 < 5; i2++) {
                PointExt[] pointExtArr = new PointExt[5];
                PointExt pointExt2 = new PointExt();
                pointSetNeutral(pointExt2);
                for (int i3 = 0; i3 < 5; i3++) {
                    pointAddVar(true, pointExt, pointExt2);
                    pointDouble(pointExt);
                    pointExtArr[i3] = pointCopy(pointExt);
                    if (i2 + i3 != 8) {
                        for (int i4 = 1; i4 < 18; i4++) {
                            pointDouble(pointExt);
                        }
                    }
                }
                PointExt[] pointExtArr2 = new PointExt[16];
                int i5 = 0 + 1;
                pointExtArr2[0] = pointExt2;
                for (int i6 = 0; i6 < 4; i6++) {
                    int i7 = 1 << i6;
                    int i8 = 0;
                    while (i8 < i7) {
                        pointExtArr2[i5] = pointCopy(pointExtArr2[i5 - i7]);
                        pointAddVar(false, pointExtArr[i6], pointExtArr2[i5]);
                        i8++;
                        i5++;
                    }
                }
                int[] createTable = C0324F.createTable(16);
                int[] create = C0324F.create();
                C0324F.copy(pointExtArr2[0].f785z, 0, create, 0);
                C0324F.copy(create, 0, createTable, 0);
                int i9 = 0;
                while (true) {
                    i9++;
                    if (i9 >= 16) {
                        break;
                    }
                    C0324F.mul(create, pointExtArr2[i9].f785z, create);
                    C0324F.copy(create, 0, createTable, i9 * 16);
                }
                C0324F.invVar(create, create);
                int i10 = i9 - 1;
                int[] create2 = C0324F.create();
                while (i10 > 0) {
                    int i11 = i10;
                    i10--;
                    C0324F.copy(createTable, i10 * 16, create2, 0);
                    C0324F.mul(create2, create, create2);
                    C0324F.copy(create2, 0, createTable, i11 * 16);
                    C0324F.mul(create, pointExtArr2[i11].f785z, create);
                }
                C0324F.copy(create, 0, createTable, 0);
                for (int i12 = 0; i12 < 16; i12++) {
                    PointExt pointExt3 = pointExtArr2[i12];
                    C0324F.copy(createTable, i12 * 16, pointExt3.f785z, 0);
                    C0324F.mul(pointExt3.f783x, pointExt3.f785z, pointExt3.f783x);
                    C0324F.mul(pointExt3.f784y, pointExt3.f785z, pointExt3.f784y);
                    C0324F.copy(pointExt3.f783x, 0, precompBase, i);
                    int i13 = i + 16;
                    C0324F.copy(pointExt3.f784y, 0, precompBase, i13);
                    i = i13 + 16;
                }
            }
        }
    }

    private static void pruneScalar(byte[] bArr, int i, byte[] bArr2) {
        System.arraycopy(bArr, i, bArr2, 0, 56);
        bArr2[0] = (byte) (bArr2[0] & 252);
        bArr2[55] = (byte) (bArr2[55] | 128);
        bArr2[56] = 0;
    }

    private static byte[] reduceScalar(byte[] bArr) {
        long decode32 = decode32(bArr, 0) & M32L;
        long decode24 = (decode24(bArr, 4) << 4) & M32L;
        long decode322 = decode32(bArr, 7) & M32L;
        long decode242 = (decode24(bArr, 11) << 4) & M32L;
        long decode323 = decode32(bArr, 14) & M32L;
        long decode243 = (decode24(bArr, 18) << 4) & M32L;
        long decode324 = decode32(bArr, 21) & M32L;
        long decode244 = (decode24(bArr, 25) << 4) & M32L;
        long decode325 = decode32(bArr, 28) & M32L;
        long decode245 = (decode24(bArr, 32) << 4) & M32L;
        long decode326 = decode32(bArr, 35) & M32L;
        long decode246 = (decode24(bArr, 39) << 4) & M32L;
        long decode327 = decode32(bArr, 42) & M32L;
        long decode247 = (decode24(bArr, 46) << 4) & M32L;
        long decode328 = decode32(bArr, 49) & M32L;
        long decode248 = (decode24(bArr, 53) << 4) & M32L;
        long decode329 = decode32(bArr, 56) & M32L;
        long decode249 = (decode24(bArr, 60) << 4) & M32L;
        long decode3210 = decode32(bArr, 63) & M32L;
        long decode2410 = (decode24(bArr, 67) << 4) & M32L;
        long decode3211 = decode32(bArr, 70) & M32L;
        long decode2411 = (decode24(bArr, 74) << 4) & M32L;
        long decode3212 = decode32(bArr, 77) & M32L;
        long decode2412 = (decode24(bArr, 81) << 4) & M32L;
        long decode3213 = decode32(bArr, 84) & M32L;
        long decode2413 = (decode24(bArr, 88) << 4) & M32L;
        long decode3214 = decode32(bArr, 91) & M32L;
        long decode2414 = (decode24(bArr, 95) << 4) & M32L;
        long decode3215 = decode32(bArr, 98) & M32L;
        long decode2415 = (decode24(bArr, Opcode.FSUB) << 4) & M32L;
        long decode3216 = decode32(bArr, Opcode.LMUL) & M32L;
        long decode2416 = (decode24(bArr, Opcode.LDIV) << 4) & M32L;
        long decode16 = decode16(bArr, Opcode.IREM) & M32L;
        long j = decode329 + (decode16 * 43969588);
        long j2 = decode249 + (decode16 * 30366549);
        long j3 = decode3210 + (decode16 * 163752818);
        long j4 = decode2410 + (decode16 * 258169998);
        long j5 = decode3211 + (decode16 * 96434764);
        long j6 = decode2411 + (decode16 * 227822194);
        long j7 = decode3212 + (decode16 * 149865618);
        long j8 = decode2412 + (decode16 * 550336261);
        long j9 = decode2416 + (decode3216 >>> 28);
        long j10 = decode3216 & M28L;
        long j11 = decode248 + (j9 * 43969588);
        long j12 = j + (j9 * 30366549);
        long j13 = j2 + (j9 * 163752818);
        long j14 = j3 + (j9 * 258169998);
        long j15 = j4 + (j9 * 96434764);
        long j16 = j5 + (j9 * 227822194);
        long j17 = j6 + (j9 * 149865618);
        long j18 = j7 + (j9 * 550336261);
        long j19 = decode328 + (j10 * 43969588);
        long j20 = j11 + (j10 * 30366549);
        long j21 = j12 + (j10 * 163752818);
        long j22 = j13 + (j10 * 258169998);
        long j23 = j14 + (j10 * 96434764);
        long j24 = j15 + (j10 * 227822194);
        long j25 = j16 + (j10 * 149865618);
        long j26 = j17 + (j10 * 550336261);
        long j27 = decode2415 + (decode3215 >>> 28);
        long j28 = decode3215 & M28L;
        long j29 = decode247 + (j27 * 43969588);
        long j30 = j19 + (j27 * 30366549);
        long j31 = j20 + (j27 * 163752818);
        long j32 = j21 + (j27 * 258169998);
        long j33 = j22 + (j27 * 96434764);
        long j34 = j23 + (j27 * 227822194);
        long j35 = j24 + (j27 * 149865618);
        long j36 = j25 + (j27 * 550336261);
        long j37 = decode327 + (j28 * 43969588);
        long j38 = j29 + (j28 * 30366549);
        long j39 = j30 + (j28 * 163752818);
        long j40 = j31 + (j28 * 258169998);
        long j41 = j32 + (j28 * 96434764);
        long j42 = j33 + (j28 * 227822194);
        long j43 = j34 + (j28 * 149865618);
        long j44 = j35 + (j28 * 550336261);
        long j45 = decode2414 + (decode3214 >>> 28);
        long j46 = decode3214 & M28L;
        long j47 = decode246 + (j45 * 43969588);
        long j48 = j37 + (j45 * 30366549);
        long j49 = j38 + (j45 * 163752818);
        long j50 = j39 + (j45 * 258169998);
        long j51 = j40 + (j45 * 96434764);
        long j52 = j41 + (j45 * 227822194);
        long j53 = j42 + (j45 * 149865618);
        long j54 = j43 + (j45 * 550336261);
        long j55 = decode326 + (j46 * 43969588);
        long j56 = j47 + (j46 * 30366549);
        long j57 = j48 + (j46 * 163752818);
        long j58 = j49 + (j46 * 258169998);
        long j59 = j50 + (j46 * 96434764);
        long j60 = j51 + (j46 * 227822194);
        long j61 = j52 + (j46 * 149865618);
        long j62 = j53 + (j46 * 550336261);
        long j63 = decode2413 + (decode3213 >>> 28);
        long j64 = decode3213 & M28L;
        long j65 = decode245 + (j63 * 43969588);
        long j66 = j55 + (j63 * 30366549);
        long j67 = j56 + (j63 * 163752818);
        long j68 = j57 + (j63 * 258169998);
        long j69 = j58 + (j63 * 96434764);
        long j70 = j59 + (j63 * 227822194);
        long j71 = j60 + (j63 * 149865618);
        long j72 = j61 + (j63 * 550336261);
        long j73 = j26 + (j36 >>> 28);
        long j74 = j36 & M28L;
        long j75 = j18 + (j73 >>> 28);
        long j76 = j73 & M28L;
        long j77 = j8 + (j75 >>> 28);
        long j78 = j75 & M28L;
        long j79 = j64 + (j77 >>> 28);
        long j80 = j77 & M28L;
        long j81 = decode325 + (j79 * 43969588);
        long j82 = j65 + (j79 * 30366549);
        long j83 = j66 + (j79 * 163752818);
        long j84 = j67 + (j79 * 258169998);
        long j85 = j68 + (j79 * 96434764);
        long j86 = j69 + (j79 * 227822194);
        long j87 = j70 + (j79 * 149865618);
        long j88 = j71 + (j79 * 550336261);
        long j89 = decode244 + (j80 * 43969588);
        long j90 = j81 + (j80 * 30366549);
        long j91 = j82 + (j80 * 163752818);
        long j92 = j83 + (j80 * 258169998);
        long j93 = j84 + (j80 * 96434764);
        long j94 = j85 + (j80 * 227822194);
        long j95 = j86 + (j80 * 149865618);
        long j96 = j87 + (j80 * 550336261);
        long j97 = decode324 + (j78 * 43969588);
        long j98 = j89 + (j78 * 30366549);
        long j99 = j90 + (j78 * 163752818);
        long j100 = j91 + (j78 * 258169998);
        long j101 = j92 + (j78 * 96434764);
        long j102 = j93 + (j78 * 227822194);
        long j103 = j94 + (j78 * 149865618);
        long j104 = j95 + (j78 * 550336261);
        long j105 = j54 + (j62 >>> 28);
        long j106 = j62 & M28L;
        long j107 = j44 + (j105 >>> 28);
        long j108 = j105 & M28L;
        long j109 = j74 + (j107 >>> 28);
        long j110 = j107 & M28L;
        long j111 = j76 + (j109 >>> 28);
        long j112 = j109 & M28L;
        long j113 = decode243 + (j111 * 43969588);
        long j114 = j97 + (j111 * 30366549);
        long j115 = j98 + (j111 * 163752818);
        long j116 = j99 + (j111 * 258169998);
        long j117 = j100 + (j111 * 96434764);
        long j118 = j101 + (j111 * 227822194);
        long j119 = j102 + (j111 * 149865618);
        long j120 = j103 + (j111 * 550336261);
        long j121 = decode323 + (j112 * 43969588);
        long j122 = j113 + (j112 * 30366549);
        long j123 = j114 + (j112 * 163752818);
        long j124 = j115 + (j112 * 258169998);
        long j125 = j116 + (j112 * 96434764);
        long j126 = j117 + (j112 * 227822194);
        long j127 = j118 + (j112 * 149865618);
        long j128 = j119 + (j112 * 550336261);
        long j129 = decode242 + (j110 * 43969588);
        long j130 = j121 + (j110 * 30366549);
        long j131 = j122 + (j110 * 163752818);
        long j132 = j123 + (j110 * 258169998);
        long j133 = j124 + (j110 * 96434764);
        long j134 = j125 + (j110 * 227822194);
        long j135 = j126 + (j110 * 149865618);
        long j136 = j127 + (j110 * 550336261);
        long j137 = j88 + (j96 >>> 28);
        long j138 = j96 & M28L;
        long j139 = j72 + (j137 >>> 28);
        long j140 = j137 & M28L;
        long j141 = j106 + (j139 >>> 28);
        long j142 = j139 & M28L;
        long j143 = j108 + (j141 >>> 28);
        long j144 = j141 & M28L;
        long j145 = decode322 + (j143 * 43969588);
        long j146 = j129 + (j143 * 30366549);
        long j147 = j130 + (j143 * 163752818);
        long j148 = j131 + (j143 * 258169998);
        long j149 = j132 + (j143 * 96434764);
        long j150 = j133 + (j143 * 227822194);
        long j151 = j134 + (j143 * 149865618);
        long j152 = j135 + (j143 * 550336261);
        long j153 = decode24 + (j144 * 43969588);
        long j154 = j145 + (j144 * 30366549);
        long j155 = j146 + (j144 * 163752818);
        long j156 = j147 + (j144 * 258169998);
        long j157 = j148 + (j144 * 96434764);
        long j158 = j149 + (j144 * 227822194);
        long j159 = j150 + (j144 * 149865618);
        long j160 = j151 + (j144 * 550336261);
        long j161 = (j142 * 4) + (j140 >>> 26);
        long j162 = j140 & M26L;
        long j163 = j161 + 1;
        long j164 = decode32 + (j163 * 78101261);
        long j165 = j153 + (j163 * 141809365);
        long j166 = j154 + (j163 * 175155932);
        long j167 = j155 + (j163 * 64542499);
        long j168 = j156 + (j163 * 158326419);
        long j169 = j157 + (j163 * 191173276);
        long j170 = j158 + (j163 * 104575268);
        long j171 = j159 + (j163 * 137584065);
        long j172 = j165 + (j164 >>> 28);
        long j173 = j164 & M28L;
        long j174 = j166 + (j172 >>> 28);
        long j175 = j172 & M28L;
        long j176 = j167 + (j174 >>> 28);
        long j177 = j174 & M28L;
        long j178 = j168 + (j176 >>> 28);
        long j179 = j176 & M28L;
        long j180 = j169 + (j178 >>> 28);
        long j181 = j178 & M28L;
        long j182 = j170 + (j180 >>> 28);
        long j183 = j180 & M28L;
        long j184 = j171 + (j182 >>> 28);
        long j185 = j182 & M28L;
        long j186 = j160 + (j184 >>> 28);
        long j187 = j184 & M28L;
        long j188 = j152 + (j186 >>> 28);
        long j189 = j186 & M28L;
        long j190 = j136 + (j188 >>> 28);
        long j191 = j188 & M28L;
        long j192 = j128 + (j190 >>> 28);
        long j193 = j190 & M28L;
        long j194 = j120 + (j192 >>> 28);
        long j195 = j192 & M28L;
        long j196 = j104 + (j194 >>> 28);
        long j197 = j194 & M28L;
        long j198 = j138 + (j196 >>> 28);
        long j199 = j196 & M28L;
        long j200 = j162 + (j198 >>> 28);
        long j201 = j198 & M28L;
        long j202 = j200 >>> 26;
        long j203 = j200 & M26L;
        long j204 = j202 - 1;
        long j205 = j173 - (j204 & 78101261);
        long j206 = j175 - (j204 & 141809365);
        long j207 = j177 - (j204 & 175155932);
        long j208 = j179 - (j204 & 64542499);
        long j209 = j181 - (j204 & 158326419);
        long j210 = j183 - (j204 & 191173276);
        long j211 = j185 - (j204 & 104575268);
        long j212 = j187 - (j204 & 137584065);
        long j213 = j206 + (j205 >> 28);
        long j214 = j205 & M28L;
        long j215 = j207 + (j213 >> 28);
        long j216 = j213 & M28L;
        long j217 = j208 + (j215 >> 28);
        long j218 = j215 & M28L;
        long j219 = j209 + (j217 >> 28);
        long j220 = j217 & M28L;
        long j221 = j210 + (j219 >> 28);
        long j222 = j219 & M28L;
        long j223 = j211 + (j221 >> 28);
        long j224 = j221 & M28L;
        long j225 = j212 + (j223 >> 28);
        long j226 = j223 & M28L;
        long j227 = j189 + (j225 >> 28);
        long j228 = j225 & M28L;
        long j229 = j191 + (j227 >> 28);
        long j230 = j227 & M28L;
        long j231 = j193 + (j229 >> 28);
        long j232 = j229 & M28L;
        long j233 = j195 + (j231 >> 28);
        long j234 = j231 & M28L;
        long j235 = j197 + (j233 >> 28);
        long j236 = j233 & M28L;
        long j237 = j199 + (j235 >> 28);
        long j238 = j235 & M28L;
        long j239 = j201 + (j237 >> 28);
        long j240 = j237 & M28L;
        long j241 = j203 + (j239 >> 28);
        long j242 = j239 & M28L;
        byte[] bArr2 = new byte[57];
        encode56(j214 | (j216 << 28), bArr2, 0);
        encode56(j218 | (j220 << 28), bArr2, 7);
        encode56(j222 | (j224 << 28), bArr2, 14);
        encode56(j226 | (j228 << 28), bArr2, 21);
        encode56(j230 | (j232 << 28), bArr2, 28);
        encode56(j234 | (j236 << 28), bArr2, 35);
        encode56(j238 | (j240 << 28), bArr2, 42);
        encode56(j242 | (j241 << 28), bArr2, 49);
        return bArr2;
    }

    private static void scalarMult(byte[] bArr, PointExt pointExt, PointExt pointExt2) {
        int[] iArr = new int[14];
        decodeScalar(bArr, 0, iArr);
        Nat.shiftDownBits(14, iArr, 2, 0);
        Nat.cadd(14, (iArr[0] ^ (-1)) & 1, iArr, f782L, iArr);
        Nat.shiftDownBit(14, iArr, 1);
        int[] pointPrecompute = pointPrecompute(pointExt, 8);
        PointExt pointExt3 = new PointExt();
        pointLookup(iArr, Opcode.DDIV, pointPrecompute, pointExt2);
        for (int i = 110; i >= 0; i--) {
            for (int i2 = 0; i2 < 4; i2++) {
                pointDouble(pointExt2);
            }
            pointLookup(iArr, i, pointPrecompute, pointExt3);
            pointAdd(pointExt3, pointExt2);
        }
        for (int i3 = 0; i3 < 2; i3++) {
            pointDouble(pointExt2);
        }
    }

    private static void scalarMultBase(byte[] bArr, PointExt pointExt) {
        precompute();
        int[] iArr = new int[15];
        decodeScalar(bArr, 0, iArr);
        iArr[14] = 4 + Nat.cadd(14, (iArr[0] ^ (-1)) & 1, iArr, f782L, iArr);
        Nat.shiftDownBit(iArr.length, iArr, 0);
        PointPrecomp pointPrecomp = new PointPrecomp();
        pointSetNeutral(pointExt);
        int i = 17;
        while (true) {
            int i2 = i;
            for (int i3 = 0; i3 < 5; i3++) {
                int i4 = 0;
                for (int i5 = 0; i5 < 5; i5++) {
                    i4 = (i4 & ((1 << i5) ^ (-1))) ^ ((iArr[i2 >>> 5] >>> (i2 & 31)) << i5);
                    i2 += 18;
                }
                int i6 = (i4 >>> 4) & 1;
                pointLookup(i3, (i4 ^ (-i6)) & 15, pointPrecomp);
                C0324F.cnegate(i6, pointPrecomp.f786x);
                pointAddPrecomp(pointPrecomp, pointExt);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointExt);
        }
    }

    private static void scalarMultBaseEncoded(byte[] bArr, byte[] bArr2, int i) {
        PointExt pointExt = new PointExt();
        scalarMultBase(bArr, pointExt);
        if (0 == encodePoint(pointExt, bArr2, i)) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseXY(X448.Friend friend, byte[] bArr, int i, int[] iArr, int[] iArr2) {
        if (null == friend) {
            throw new NullPointerException("This method is only for use by X448");
        }
        byte[] bArr2 = new byte[57];
        pruneScalar(bArr, i, bArr2);
        PointExt pointExt = new PointExt();
        scalarMultBase(bArr2, pointExt);
        if (0 == checkPoint(pointExt.f783x, pointExt.f784y, pointExt.f785z)) {
            throw new IllegalStateException();
        }
        C0324F.copy(pointExt.f783x, 0, iArr, 0);
        C0324F.copy(pointExt.f784y, 0, iArr2, 0);
    }

    private static void scalarMultOrderVar(PointExt pointExt, PointExt pointExt2) {
        byte[] wnafVar = getWnafVar(f782L, 5);
        PointExt[] pointPrecomputeVar = pointPrecomputeVar(pointExt, 8);
        pointSetNeutral(pointExt2);
        int i = 446;
        while (true) {
            byte b = wnafVar[i];
            if (b != 0) {
                int i2 = b >> 31;
                pointAddVar(i2 != 0, pointPrecomputeVar[(b ^ i2) >>> 1], pointExt2);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointExt2);
        }
    }

    private static void scalarMultStrausVar(int[] iArr, int[] iArr2, PointExt pointExt, PointExt pointExt2) {
        precompute();
        byte[] wnafVar = getWnafVar(iArr, 7);
        byte[] wnafVar2 = getWnafVar(iArr2, 5);
        PointExt[] pointPrecomputeVar = pointPrecomputeVar(pointExt, 8);
        pointSetNeutral(pointExt2);
        int i = 446;
        while (true) {
            byte b = wnafVar[i];
            if (b != 0) {
                int i2 = b >> 31;
                pointAddVar(i2 != 0, precompBaseTable[(b ^ i2) >>> 1], pointExt2);
            }
            byte b2 = wnafVar2[i];
            if (b2 != 0) {
                int i3 = b2 >> 31;
                pointAddVar(i3 != 0, pointPrecomputeVar[(b2 ^ i3) >>> 1], pointExt2);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointExt2);
        }
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        implSign(bArr, i, bArr2, (byte) 0, bArr3, i2, i3, bArr4, i4);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4, byte[] bArr5, int i5) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4, bArr5, i5);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, byte[] bArr4, int i3) {
        implSign(bArr, i, bArr2, (byte) 1, bArr3, i2, 64, bArr4, i3);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, byte[] bArr5, int i4) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64, bArr5, i4);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, Xof xof, byte[] bArr3, int i2) {
        byte[] bArr4 = new byte[64];
        if (64 != xof.doFinal(bArr4, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, (byte) 1, bArr4, 0, bArr4.length, bArr3, i2);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Xof xof, byte[] bArr4, int i3) {
        byte[] bArr5 = new byte[64];
        if (64 != xof.doFinal(bArr5, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr5, 0, bArr5.length, bArr4, i3);
    }

    public static boolean validatePublicKeyFull(byte[] bArr, int i) {
        PointExt pointExt = new PointExt();
        if (decodePointVar(bArr, i, false, pointExt)) {
            C0324F.normalize(pointExt.f783x);
            C0324F.normalize(pointExt.f784y);
            C0324F.normalize(pointExt.f785z);
            if (isNeutralElementVar(pointExt.f783x, pointExt.f784y, pointExt.f785z)) {
                return false;
            }
            PointExt pointExt2 = new PointExt();
            scalarMultOrderVar(pointExt, pointExt2);
            C0324F.normalize(pointExt2.f783x);
            C0324F.normalize(pointExt2.f784y);
            C0324F.normalize(pointExt2.f785z);
            return isNeutralElementVar(pointExt2.f783x, pointExt2.f784y, pointExt2.f785z);
        }
        return false;
    }

    public static boolean validatePublicKeyPartial(byte[] bArr, int i) {
        return decodePointVar(bArr, i, false, new PointExt());
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Xof xof) {
        byte[] bArr4 = new byte[64];
        if (64 != xof.doFinal(bArr4, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, 0, bArr4.length);
    }
}