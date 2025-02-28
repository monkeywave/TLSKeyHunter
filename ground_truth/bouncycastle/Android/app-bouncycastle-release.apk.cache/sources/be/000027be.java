package org.bouncycastle.math.p016ec.rfc8032;

import java.security.SecureRandom;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.p016ec.rfc7748.X25519;
import org.bouncycastle.math.p016ec.rfc7748.X25519Field;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519 */
/* loaded from: classes2.dex */
public abstract class Ed25519 {
    private static final int COORD_INTS = 8;
    private static final int POINT_BYTES = 32;
    private static final int PRECOMP_BLOCKS = 8;
    private static final int PRECOMP_MASK = 7;
    private static final int PRECOMP_POINTS = 8;
    private static final int PRECOMP_RANGE = 256;
    private static final int PRECOMP_SPACING = 8;
    private static final int PRECOMP_TEETH = 4;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 32;
    private static final int SCALAR_BYTES = 32;
    private static final int SCALAR_INTS = 8;
    public static final int SECRET_KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = 64;
    private static final int WNAF_WIDTH_128 = 4;
    private static final int WNAF_WIDTH_BASE = 6;
    private static final byte[] DOM2_PREFIX = {83, 105, 103, 69, 100, 50, 53, 53, 49, 57, 32, 110, 111, 32, 69, 100, 50, 53, 53, 49, 57, 32, 99, 111, 108, 108, 105, 115, 105, 111, 110, 115};

    /* renamed from: P */
    private static final int[] f1102P = {-19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE};
    private static final int[] ORDER8_y1 = {1886001095, 1339575613, 1980447930, 258412557, -95215574, -959694548, 2013120334, 2047061138};
    private static final int[] ORDER8_y2 = {-1886001114, -1339575614, -1980447931, -258412558, 95215573, 959694547, -2013120335, 100422509};
    private static final int[] B_x = {52811034, 25909283, 8072341, 50637101, 13785486, 30858332, 20483199, 20966410, 43936626, 4379245};
    private static final int[] B_y = {40265304, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545, 6710886, 53687091, 13421772};
    private static final int[] B128_x = {12052516, 1174424, 4087752, 38672185, 20040971, 21899680, 55468344, 20105554, 66708015, 9981791};
    private static final int[] B128_y = {66430571, 45040722, 4842939, 15895846, 18981244, 46308410, 4697481, 8903007, 53646190, 12474675};
    private static final int[] C_d = {56195235, 47411844, 25868126, 40503822, 57364, 58321048, 30416477, 31930572, 57760639, 10749657};
    private static final int[] C_d2 = {45281625, 27714825, 18181821, 13898781, 114729, 49533232, 60832955, 30306712, 48412415, 4722099};
    private static final int[] C_d4 = {23454386, 55429651, 2809210, 27797563, 229458, 31957600, 54557047, 27058993, 29715967, 9444199};
    private static final Object PRECOMP_LOCK = new Object();
    private static PointPrecomp[] PRECOMP_BASE_WNAF = null;
    private static PointPrecomp[] PRECOMP_BASE128_WNAF = null;
    private static int[] PRECOMP_BASE_COMB = null;

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$Algorithm */
    /* loaded from: classes2.dex */
    public static final class Algorithm {
        public static final int Ed25519 = 0;
        public static final int Ed25519ctx = 1;
        public static final int Ed25519ph = 2;
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$F */
    /* loaded from: classes2.dex */
    private static class C1378F extends X25519Field {
        private C1378F() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointAccum */
    /* loaded from: classes2.dex */
    public static class PointAccum {

        /* renamed from: u */
        int[] f1103u;

        /* renamed from: v */
        int[] f1104v;

        /* renamed from: x */
        int[] f1105x;

        /* renamed from: y */
        int[] f1106y;

        /* renamed from: z */
        int[] f1107z;

        private PointAccum() {
            this.f1105x = C1378F.create();
            this.f1106y = C1378F.create();
            this.f1107z = C1378F.create();
            this.f1103u = C1378F.create();
            this.f1104v = C1378F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointAffine */
    /* loaded from: classes2.dex */
    public static class PointAffine {

        /* renamed from: x */
        int[] f1108x;

        /* renamed from: y */
        int[] f1109y;

        private PointAffine() {
            this.f1108x = C1378F.create();
            this.f1109y = C1378F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointExtended */
    /* loaded from: classes2.dex */
    public static class PointExtended {

        /* renamed from: t */
        int[] f1110t;

        /* renamed from: x */
        int[] f1111x;

        /* renamed from: y */
        int[] f1112y;

        /* renamed from: z */
        int[] f1113z;

        private PointExtended() {
            this.f1111x = C1378F.create();
            this.f1112y = C1378F.create();
            this.f1113z = C1378F.create();
            this.f1110t = C1378F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointPrecomp */
    /* loaded from: classes2.dex */
    public static class PointPrecomp {
        int[] xyd;
        int[] ymx_h;
        int[] ypx_h;

        private PointPrecomp() {
            this.ymx_h = C1378F.create();
            this.ypx_h = C1378F.create();
            this.xyd = C1378F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointPrecompZ */
    /* loaded from: classes2.dex */
    public static class PointPrecompZ {
        int[] xyd;
        int[] ymx_h;
        int[] ypx_h;

        /* renamed from: z */
        int[] f1114z;

        private PointPrecompZ() {
            this.ymx_h = C1378F.create();
            this.ypx_h = C1378F.create();
            this.xyd = C1378F.create();
            this.f1114z = C1378F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointTemp */
    /* loaded from: classes2.dex */
    public static class PointTemp {

        /* renamed from: r0 */
        int[] f1115r0;

        /* renamed from: r1 */
        int[] f1116r1;

        private PointTemp() {
            this.f1115r0 = C1378F.create();
            this.f1116r1 = C1378F.create();
        }
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PublicPoint */
    /* loaded from: classes2.dex */
    public static final class PublicPoint {
        final int[] data;

        PublicPoint(int[] iArr) {
            this.data = iArr;
        }
    }

    private static byte[] calculateS(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int[] iArr = new int[16];
        Scalar25519.decode(bArr, iArr);
        int[] iArr2 = new int[8];
        Scalar25519.decode(bArr2, iArr2);
        int[] iArr3 = new int[8];
        Scalar25519.decode(bArr3, iArr3);
        Nat256.mulAddTo(iArr2, iArr3, iArr);
        byte[] bArr4 = new byte[64];
        Codec.encode32(iArr, 0, 16, bArr4, 0);
        return Scalar25519.reduce512(bArr4);
    }

    private static boolean checkContextVar(byte[] bArr, byte b) {
        return (bArr == null && b == 0) || (bArr != null && bArr.length < 256);
    }

    private static int checkPoint(PointAccum pointAccum) {
        int[] create = C1378F.create();
        int[] create2 = C1378F.create();
        int[] create3 = C1378F.create();
        int[] create4 = C1378F.create();
        C1378F.sqr(pointAccum.f1105x, create2);
        C1378F.sqr(pointAccum.f1106y, create3);
        C1378F.sqr(pointAccum.f1107z, create4);
        C1378F.mul(create2, create3, create);
        C1378F.sub(create2, create3, create2);
        C1378F.mul(create2, create4, create2);
        C1378F.sqr(create4, create4);
        C1378F.mul(create, C_d, create);
        C1378F.add(create, create4, create);
        C1378F.add(create, create2, create);
        C1378F.normalize(create);
        C1378F.normalize(create3);
        C1378F.normalize(create4);
        return C1378F.isZero(create) & (~C1378F.isZero(create3)) & (~C1378F.isZero(create4));
    }

    private static int checkPoint(PointAffine pointAffine) {
        int[] create = C1378F.create();
        int[] create2 = C1378F.create();
        int[] create3 = C1378F.create();
        C1378F.sqr(pointAffine.f1108x, create2);
        C1378F.sqr(pointAffine.f1109y, create3);
        C1378F.mul(create2, create3, create);
        C1378F.sub(create2, create3, create2);
        C1378F.mul(create, C_d, create);
        C1378F.addOne(create);
        C1378F.add(create, create2, create);
        C1378F.normalize(create);
        C1378F.normalize(create3);
        return C1378F.isZero(create) & (~C1378F.isZero(create3));
    }

    private static boolean checkPointFullVar(byte[] bArr) {
        int decode32 = Codec.decode32(bArr, 28) & Integer.MAX_VALUE;
        int i = f1102P[7] ^ decode32;
        int i2 = ORDER8_y1[7] ^ decode32;
        int i3 = ORDER8_y2[7] ^ decode32;
        for (int i4 = 6; i4 > 0; i4--) {
            int decode322 = Codec.decode32(bArr, i4 * 4);
            decode32 |= decode322;
            i |= f1102P[i4] ^ decode322;
            i2 |= ORDER8_y1[i4] ^ decode322;
            i3 |= decode322 ^ ORDER8_y2[i4];
        }
        int decode323 = Codec.decode32(bArr, 0);
        if (decode32 != 0 || decode323 - 2147483648 > -2147483647) {
            if (i != 0 || Integer.MIN_VALUE + decode323 < f1102P[0] - (-2147483647)) {
                return (((ORDER8_y1[0] ^ decode323) | i2) != 0) & (((decode323 ^ ORDER8_y2[0]) | i3) != 0);
            }
            return false;
        }
        return false;
    }

    private static boolean checkPointOrderVar(PointAffine pointAffine) {
        PointAccum pointAccum = new PointAccum();
        scalarMultOrderVar(pointAffine, pointAccum);
        return normalizeToNeutralElementVar(pointAccum);
    }

    private static boolean checkPointVar(byte[] bArr) {
        int decode32 = Codec.decode32(bArr, 28) & Integer.MAX_VALUE;
        int[] iArr = f1102P;
        if (decode32 < iArr[7]) {
            return true;
        }
        int[] iArr2 = new int[8];
        Codec.decode32(bArr, 0, iArr2, 0, 8);
        iArr2[7] = iArr2[7] & Integer.MAX_VALUE;
        return !Nat256.gte(iArr2, iArr);
    }

    private static byte[] copy(byte[] bArr, int i, int i2) {
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        return bArr2;
    }

    private static Digest createDigest() {
        SHA512Digest sHA512Digest = new SHA512Digest();
        if (sHA512Digest.getDigestSize() == 64) {
            return sHA512Digest;
        }
        throw new IllegalStateException();
    }

    public static Digest createPrehash() {
        return createDigest();
    }

    private static boolean decodePointVar(byte[] bArr, boolean z, PointAffine pointAffine) {
        int i = (bArr[31] & ByteCompanionObject.MIN_VALUE) >>> 7;
        C1378F.decode(bArr, pointAffine.f1109y);
        int[] create = C1378F.create();
        int[] create2 = C1378F.create();
        C1378F.sqr(pointAffine.f1109y, create);
        C1378F.mul(C_d, create, create2);
        C1378F.subOne(create);
        C1378F.addOne(create2);
        if (C1378F.sqrtRatioVar(create, create2, pointAffine.f1108x)) {
            C1378F.normalize(pointAffine.f1108x);
            if (i == 1 && C1378F.isZeroVar(pointAffine.f1108x)) {
                return false;
            }
            if (z ^ (i != (pointAffine.f1108x[0] & 1))) {
                C1378F.negate(pointAffine.f1108x, pointAffine.f1108x);
                C1378F.normalize(pointAffine.f1108x);
            }
            return true;
        }
        return false;
    }

    private static void dom2(Digest digest, byte b, byte[] bArr) {
        byte[] bArr2 = DOM2_PREFIX;
        int length = bArr2.length;
        int i = length + 2;
        int length2 = bArr.length + i;
        byte[] bArr3 = new byte[length2];
        System.arraycopy(bArr2, 0, bArr3, 0, length);
        bArr3[length] = b;
        bArr3[length + 1] = (byte) bArr.length;
        System.arraycopy(bArr, 0, bArr3, i, bArr.length);
        digest.update(bArr3, 0, length2);
    }

    private static void encodePoint(PointAffine pointAffine, byte[] bArr, int i) {
        C1378F.encode(pointAffine.f1109y, bArr, i);
        int i2 = i + 31;
        bArr[i2] = (byte) (((pointAffine.f1108x[0] & 1) << 7) | bArr[i2]);
    }

    public static void encodePublicPoint(PublicPoint publicPoint, byte[] bArr, int i) {
        C1378F.encode(publicPoint.data, 10, bArr, i);
        int i2 = i + 31;
        bArr[i2] = (byte) (((publicPoint.data[0] & 1) << 7) | bArr[i2]);
    }

    private static int encodeResult(PointAccum pointAccum, byte[] bArr, int i) {
        PointAffine pointAffine = new PointAffine();
        normalizeToAffine(pointAccum, pointAffine);
        int checkPoint = checkPoint(pointAffine);
        encodePoint(pointAffine, bArr, i);
        return checkPoint;
    }

    private static PublicPoint exportPoint(PointAffine pointAffine) {
        int[] iArr = new int[20];
        C1378F.copy(pointAffine.f1108x, 0, iArr, 0);
        C1378F.copy(pointAffine.f1109y, 0, iArr, 10);
        return new PublicPoint(iArr);
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("k");
        }
        secureRandom.nextBytes(bArr);
    }

    public static PublicPoint generatePublicKey(byte[] bArr, int i) {
        Digest createDigest = createDigest();
        byte[] bArr2 = new byte[64];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr2, 0);
        byte[] bArr3 = new byte[32];
        pruneScalar(bArr2, 0, bArr3);
        PointAccum pointAccum = new PointAccum();
        scalarMultBase(bArr3, pointAccum);
        PointAffine pointAffine = new PointAffine();
        normalizeToAffine(pointAccum, pointAffine);
        if (checkPoint(pointAffine) != 0) {
            return exportPoint(pointAffine);
        }
        throw new IllegalStateException();
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        Digest createDigest = createDigest();
        byte[] bArr3 = new byte[64];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr3, 0);
        byte[] bArr4 = new byte[32];
        pruneScalar(bArr3, 0, bArr4);
        scalarMultBaseEncoded(bArr4, bArr2, i2);
    }

    private static int getWindow4(int[] iArr, int i) {
        return (iArr[i >>> 3] >>> ((i & 7) << 2)) & 15;
    }

    private static void groupCombBits(int[] iArr) {
        for (int i = 0; i < iArr.length; i++) {
            iArr[i] = Interleave.shuffle2(iArr[i]);
        }
    }

    private static void implSign(Digest digest, byte[] bArr, byte[] bArr2, byte[] bArr3, int i, byte[] bArr4, byte b, byte[] bArr5, int i2, int i3, byte[] bArr6, int i4) {
        if (bArr4 != null) {
            dom2(digest, b, bArr4);
        }
        digest.update(bArr, 32, 32);
        digest.update(bArr5, i2, i3);
        digest.doFinal(bArr, 0);
        byte[] reduce512 = Scalar25519.reduce512(bArr);
        byte[] bArr7 = new byte[32];
        scalarMultBaseEncoded(reduce512, bArr7, 0);
        if (bArr4 != null) {
            dom2(digest, b, bArr4);
        }
        digest.update(bArr7, 0, 32);
        digest.update(bArr3, i, 32);
        digest.update(bArr5, i2, i3);
        digest.doFinal(bArr, 0);
        byte[] calculateS = calculateS(reduce512, Scalar25519.reduce512(bArr), bArr2);
        System.arraycopy(bArr7, 0, bArr6, i4, 32);
        System.arraycopy(calculateS, 0, bArr6, i4 + 32, 32);
    }

    private static void implSign(byte[] bArr, int i, byte[] bArr2, byte b, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        if (!checkContextVar(bArr2, b)) {
            throw new IllegalArgumentException("ctx");
        }
        Digest createDigest = createDigest();
        byte[] bArr5 = new byte[64];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr5, 0);
        byte[] bArr6 = new byte[32];
        pruneScalar(bArr5, 0, bArr6);
        byte[] bArr7 = new byte[32];
        scalarMultBaseEncoded(bArr6, bArr7, 0);
        implSign(createDigest, bArr5, bArr6, bArr7, 0, bArr2, b, bArr3, i2, i3, bArr4, i4);
    }

    private static void implSign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte b, byte[] bArr4, int i3, int i4, byte[] bArr5, int i5) {
        if (!checkContextVar(bArr3, b)) {
            throw new IllegalArgumentException("ctx");
        }
        Digest createDigest = createDigest();
        byte[] bArr6 = new byte[64];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr6, 0);
        byte[] bArr7 = new byte[32];
        pruneScalar(bArr6, 0, bArr7);
        implSign(createDigest, bArr6, bArr7, bArr2, i2, bArr3, b, bArr4, i3, i4, bArr5, i5);
    }

    private static boolean implVerify(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte b, byte[] bArr3, int i2, int i3) {
        if (checkContextVar(bArr2, b)) {
            byte[] copy = copy(bArr, i, 32);
            byte[] copy2 = copy(bArr, i + 32, 32);
            if (checkPointVar(copy)) {
                int[] iArr = new int[8];
                if (Scalar25519.checkVar(copy2, iArr)) {
                    PointAffine pointAffine = new PointAffine();
                    if (decodePointVar(copy, true, pointAffine)) {
                        PointAffine pointAffine2 = new PointAffine();
                        C1378F.negate(publicPoint.data, pointAffine2.f1108x);
                        C1378F.copy(publicPoint.data, 10, pointAffine2.f1109y, 0);
                        byte[] bArr4 = new byte[32];
                        encodePublicPoint(publicPoint, bArr4, 0);
                        Digest createDigest = createDigest();
                        byte[] bArr5 = new byte[64];
                        if (bArr2 != null) {
                            dom2(createDigest, b, bArr2);
                        }
                        createDigest.update(copy, 0, 32);
                        createDigest.update(bArr4, 0, 32);
                        createDigest.update(bArr3, i2, i3);
                        createDigest.doFinal(bArr5, 0);
                        int[] iArr2 = new int[8];
                        Scalar25519.decode(Scalar25519.reduce512(bArr5), iArr2);
                        int[] iArr3 = new int[4];
                        int[] iArr4 = new int[4];
                        if (Scalar25519.reduceBasisVar(iArr2, iArr3, iArr4)) {
                            Scalar25519.multiply128Var(iArr, iArr4, iArr);
                            PointAccum pointAccum = new PointAccum();
                            scalarMultStraus128Var(iArr, iArr3, pointAffine2, iArr4, pointAffine, pointAccum);
                            return normalizeToNeutralElementVar(pointAccum);
                        }
                        throw new IllegalStateException();
                    }
                    return false;
                }
                return false;
            }
            return false;
        }
        throw new IllegalArgumentException("ctx");
    }

    private static boolean implVerify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte b, byte[] bArr4, int i3, int i4) {
        if (checkContextVar(bArr3, b)) {
            byte[] copy = copy(bArr, i, 32);
            byte[] copy2 = copy(bArr, i + 32, 32);
            byte[] copy3 = copy(bArr2, i2, 32);
            if (checkPointVar(copy)) {
                int[] iArr = new int[8];
                if (Scalar25519.checkVar(copy2, iArr) && checkPointFullVar(copy3)) {
                    PointAffine pointAffine = new PointAffine();
                    if (decodePointVar(copy, true, pointAffine)) {
                        PointAffine pointAffine2 = new PointAffine();
                        if (decodePointVar(copy3, true, pointAffine2)) {
                            Digest createDigest = createDigest();
                            byte[] bArr5 = new byte[64];
                            if (bArr3 != null) {
                                dom2(createDigest, b, bArr3);
                            }
                            createDigest.update(copy, 0, 32);
                            createDigest.update(copy3, 0, 32);
                            createDigest.update(bArr4, i3, i4);
                            createDigest.doFinal(bArr5, 0);
                            int[] iArr2 = new int[8];
                            Scalar25519.decode(Scalar25519.reduce512(bArr5), iArr2);
                            int[] iArr3 = new int[4];
                            int[] iArr4 = new int[4];
                            if (Scalar25519.reduceBasisVar(iArr2, iArr3, iArr4)) {
                                Scalar25519.multiply128Var(iArr, iArr4, iArr);
                                PointAccum pointAccum = new PointAccum();
                                scalarMultStraus128Var(iArr, iArr3, pointAffine2, iArr4, pointAffine, pointAccum);
                                return normalizeToNeutralElementVar(pointAccum);
                            }
                            throw new IllegalStateException();
                        }
                        return false;
                    }
                    return false;
                }
                return false;
            }
            return false;
        }
        throw new IllegalArgumentException("ctx");
    }

    private static void invertDoubleZs(PointExtended[] pointExtendedArr) {
        int length = pointExtendedArr.length;
        int[] createTable = C1378F.createTable(length);
        int[] create = C1378F.create();
        C1378F.copy(pointExtendedArr[0].f1113z, 0, create, 0);
        C1378F.copy(create, 0, createTable, 0);
        int i = 0;
        while (true) {
            int i2 = i + 1;
            if (i2 >= length) {
                break;
            }
            C1378F.mul(create, pointExtendedArr[i2].f1113z, create);
            C1378F.copy(create, 0, createTable, i2 * 10);
            i = i2;
        }
        C1378F.add(create, create, create);
        C1378F.invVar(create, create);
        int[] create2 = C1378F.create();
        while (i > 0) {
            int i3 = i - 1;
            C1378F.copy(createTable, i3 * 10, create2, 0);
            C1378F.mul(create2, create, create2);
            C1378F.mul(create, pointExtendedArr[i].f1113z, create);
            C1378F.copy(create2, 0, pointExtendedArr[i].f1113z, 0);
            i = i3;
        }
        C1378F.copy(create, 0, pointExtendedArr[0].f1113z, 0);
    }

    private static void normalizeToAffine(PointAccum pointAccum, PointAffine pointAffine) {
        C1378F.inv(pointAccum.f1107z, pointAffine.f1109y);
        C1378F.mul(pointAffine.f1109y, pointAccum.f1105x, pointAffine.f1108x);
        C1378F.mul(pointAffine.f1109y, pointAccum.f1106y, pointAffine.f1109y);
        C1378F.normalize(pointAffine.f1108x);
        C1378F.normalize(pointAffine.f1109y);
    }

    private static boolean normalizeToNeutralElementVar(PointAccum pointAccum) {
        C1378F.normalize(pointAccum.f1105x);
        C1378F.normalize(pointAccum.f1106y);
        C1378F.normalize(pointAccum.f1107z);
        return C1378F.isZeroVar(pointAccum.f1105x) && !C1378F.isZeroVar(pointAccum.f1106y) && C1378F.areEqualVar(pointAccum.f1106y, pointAccum.f1107z);
    }

    private static void pointAdd(PointExtended pointExtended, PointExtended pointExtended2, PointExtended pointExtended3, PointTemp pointTemp) {
        int[] iArr = pointExtended3.f1111x;
        int[] iArr2 = pointExtended3.f1112y;
        int[] iArr3 = pointTemp.f1115r0;
        int[] iArr4 = pointTemp.f1116r1;
        C1378F.apm(pointExtended.f1112y, pointExtended.f1111x, iArr2, iArr);
        C1378F.apm(pointExtended2.f1112y, pointExtended2.f1111x, iArr4, iArr3);
        C1378F.mul(iArr, iArr3, iArr);
        C1378F.mul(iArr2, iArr4, iArr2);
        C1378F.mul(pointExtended.f1110t, pointExtended2.f1110t, iArr3);
        C1378F.mul(iArr3, C_d2, iArr3);
        C1378F.add(pointExtended.f1113z, pointExtended.f1113z, iArr4);
        C1378F.mul(iArr4, pointExtended2.f1113z, iArr4);
        C1378F.apm(iArr2, iArr, iArr2, iArr);
        C1378F.apm(iArr4, iArr3, iArr4, iArr3);
        C1378F.mul(iArr, iArr2, pointExtended3.f1110t);
        C1378F.mul(iArr3, iArr4, pointExtended3.f1113z);
        C1378F.mul(iArr, iArr3, pointExtended3.f1111x);
        C1378F.mul(iArr2, iArr4, pointExtended3.f1112y);
    }

    private static void pointAdd(PointPrecomp pointPrecomp, PointAccum pointAccum, PointTemp pointTemp) {
        int[] iArr = pointAccum.f1105x;
        int[] iArr2 = pointAccum.f1106y;
        int[] iArr3 = pointTemp.f1115r0;
        int[] iArr4 = pointAccum.f1103u;
        int[] iArr5 = pointAccum.f1104v;
        C1378F.apm(pointAccum.f1106y, pointAccum.f1105x, iArr2, iArr);
        C1378F.mul(iArr, pointPrecomp.ymx_h, iArr);
        C1378F.mul(iArr2, pointPrecomp.ypx_h, iArr2);
        C1378F.mul(pointAccum.f1103u, pointAccum.f1104v, iArr3);
        C1378F.mul(iArr3, pointPrecomp.xyd, iArr3);
        C1378F.apm(iArr2, iArr, iArr5, iArr4);
        C1378F.apm(pointAccum.f1107z, iArr3, iArr2, iArr);
        C1378F.mul(iArr, iArr2, pointAccum.f1107z);
        C1378F.mul(iArr, iArr4, pointAccum.f1105x);
        C1378F.mul(iArr2, iArr5, pointAccum.f1106y);
    }

    private static void pointAdd(PointPrecompZ pointPrecompZ, PointAccum pointAccum, PointTemp pointTemp) {
        int[] iArr = pointAccum.f1105x;
        int[] iArr2 = pointAccum.f1106y;
        int[] iArr3 = pointTemp.f1115r0;
        int[] iArr4 = pointAccum.f1107z;
        int[] iArr5 = pointAccum.f1103u;
        int[] iArr6 = pointAccum.f1104v;
        C1378F.apm(pointAccum.f1106y, pointAccum.f1105x, iArr2, iArr);
        C1378F.mul(iArr, pointPrecompZ.ymx_h, iArr);
        C1378F.mul(iArr2, pointPrecompZ.ypx_h, iArr2);
        C1378F.mul(pointAccum.f1103u, pointAccum.f1104v, iArr3);
        C1378F.mul(iArr3, pointPrecompZ.xyd, iArr3);
        C1378F.mul(pointAccum.f1107z, pointPrecompZ.f1114z, iArr4);
        C1378F.apm(iArr2, iArr, iArr6, iArr5);
        C1378F.apm(iArr4, iArr3, iArr2, iArr);
        C1378F.mul(iArr, iArr2, pointAccum.f1107z);
        C1378F.mul(iArr, iArr5, pointAccum.f1105x);
        C1378F.mul(iArr2, iArr6, pointAccum.f1106y);
    }

    private static void pointAddVar(boolean z, PointPrecomp pointPrecomp, PointAccum pointAccum, PointTemp pointTemp) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3 = pointAccum.f1105x;
        int[] iArr4 = pointAccum.f1106y;
        int[] iArr5 = pointTemp.f1115r0;
        int[] iArr6 = pointAccum.f1103u;
        int[] iArr7 = pointAccum.f1104v;
        if (z) {
            iArr2 = iArr3;
            iArr = iArr4;
        } else {
            iArr = iArr3;
            iArr2 = iArr4;
        }
        C1378F.apm(pointAccum.f1106y, pointAccum.f1105x, iArr4, iArr3);
        C1378F.mul(iArr, pointPrecomp.ymx_h, iArr);
        C1378F.mul(iArr2, pointPrecomp.ypx_h, iArr2);
        C1378F.mul(pointAccum.f1103u, pointAccum.f1104v, iArr5);
        C1378F.mul(iArr5, pointPrecomp.xyd, iArr5);
        C1378F.apm(iArr4, iArr3, iArr7, iArr6);
        C1378F.apm(pointAccum.f1107z, iArr5, iArr2, iArr);
        C1378F.mul(iArr3, iArr4, pointAccum.f1107z);
        C1378F.mul(iArr3, iArr6, pointAccum.f1105x);
        C1378F.mul(iArr4, iArr7, pointAccum.f1106y);
    }

    private static void pointAddVar(boolean z, PointPrecompZ pointPrecompZ, PointAccum pointAccum, PointTemp pointTemp) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3 = pointAccum.f1105x;
        int[] iArr4 = pointAccum.f1106y;
        int[] iArr5 = pointTemp.f1115r0;
        int[] iArr6 = pointAccum.f1107z;
        int[] iArr7 = pointAccum.f1103u;
        int[] iArr8 = pointAccum.f1104v;
        if (z) {
            iArr2 = iArr3;
            iArr = iArr4;
        } else {
            iArr = iArr3;
            iArr2 = iArr4;
        }
        C1378F.apm(pointAccum.f1106y, pointAccum.f1105x, iArr4, iArr3);
        C1378F.mul(iArr, pointPrecompZ.ymx_h, iArr);
        C1378F.mul(iArr2, pointPrecompZ.ypx_h, iArr2);
        C1378F.mul(pointAccum.f1103u, pointAccum.f1104v, iArr5);
        C1378F.mul(iArr5, pointPrecompZ.xyd, iArr5);
        C1378F.mul(pointAccum.f1107z, pointPrecompZ.f1114z, iArr6);
        C1378F.apm(iArr4, iArr3, iArr8, iArr7);
        C1378F.apm(iArr6, iArr5, iArr2, iArr);
        C1378F.mul(iArr3, iArr4, pointAccum.f1107z);
        C1378F.mul(iArr3, iArr7, pointAccum.f1105x);
        C1378F.mul(iArr4, iArr8, pointAccum.f1106y);
    }

    private static void pointCopy(PointAccum pointAccum, PointExtended pointExtended) {
        C1378F.copy(pointAccum.f1105x, 0, pointExtended.f1111x, 0);
        C1378F.copy(pointAccum.f1106y, 0, pointExtended.f1112y, 0);
        C1378F.copy(pointAccum.f1107z, 0, pointExtended.f1113z, 0);
        C1378F.mul(pointAccum.f1103u, pointAccum.f1104v, pointExtended.f1110t);
    }

    private static void pointCopy(PointAffine pointAffine, PointExtended pointExtended) {
        C1378F.copy(pointAffine.f1108x, 0, pointExtended.f1111x, 0);
        C1378F.copy(pointAffine.f1109y, 0, pointExtended.f1112y, 0);
        C1378F.one(pointExtended.f1113z);
        C1378F.mul(pointAffine.f1108x, pointAffine.f1109y, pointExtended.f1110t);
    }

    private static void pointCopy(PointExtended pointExtended, PointPrecompZ pointPrecompZ) {
        C1378F.apm(pointExtended.f1112y, pointExtended.f1111x, pointPrecompZ.ypx_h, pointPrecompZ.ymx_h);
        C1378F.mul(pointExtended.f1110t, C_d2, pointPrecompZ.xyd);
        C1378F.add(pointExtended.f1113z, pointExtended.f1113z, pointPrecompZ.f1114z);
    }

    private static void pointDouble(PointAccum pointAccum) {
        int[] iArr = pointAccum.f1105x;
        int[] iArr2 = pointAccum.f1106y;
        int[] iArr3 = pointAccum.f1107z;
        int[] iArr4 = pointAccum.f1103u;
        int[] iArr5 = pointAccum.f1104v;
        C1378F.add(pointAccum.f1105x, pointAccum.f1106y, iArr4);
        C1378F.sqr(pointAccum.f1105x, iArr);
        C1378F.sqr(pointAccum.f1106y, iArr2);
        C1378F.sqr(pointAccum.f1107z, iArr3);
        C1378F.add(iArr3, iArr3, iArr3);
        C1378F.apm(iArr, iArr2, iArr5, iArr2);
        C1378F.sqr(iArr4, iArr4);
        C1378F.sub(iArr5, iArr4, iArr4);
        C1378F.add(iArr3, iArr2, iArr);
        C1378F.carry(iArr);
        C1378F.mul(iArr, iArr2, pointAccum.f1107z);
        C1378F.mul(iArr, iArr4, pointAccum.f1105x);
        C1378F.mul(iArr2, iArr5, pointAccum.f1106y);
    }

    private static void pointLookup(int i, int i2, PointPrecomp pointPrecomp) {
        int i3 = i * 240;
        for (int i4 = 0; i4 < 8; i4++) {
            int i5 = ((i4 ^ i2) - 1) >> 31;
            C1378F.cmov(i5, PRECOMP_BASE_COMB, i3, pointPrecomp.ymx_h, 0);
            C1378F.cmov(i5, PRECOMP_BASE_COMB, i3 + 10, pointPrecomp.ypx_h, 0);
            C1378F.cmov(i5, PRECOMP_BASE_COMB, i3 + 20, pointPrecomp.xyd, 0);
            i3 += 30;
        }
    }

    private static void pointLookupZ(int[] iArr, int i, int[] iArr2, PointPrecompZ pointPrecompZ) {
        int window4 = getWindow4(iArr, i);
        int i2 = (window4 >>> 3) ^ 1;
        int i3 = (window4 ^ (-i2)) & 7;
        int i4 = 0;
        for (int i5 = 0; i5 < 8; i5++) {
            int i6 = ((i5 ^ i3) - 1) >> 31;
            C1378F.cmov(i6, iArr2, i4, pointPrecompZ.ymx_h, 0);
            C1378F.cmov(i6, iArr2, i4 + 10, pointPrecompZ.ypx_h, 0);
            C1378F.cmov(i6, iArr2, i4 + 20, pointPrecompZ.xyd, 0);
            C1378F.cmov(i6, iArr2, i4 + 30, pointPrecompZ.f1114z, 0);
            i4 += 40;
        }
        C1378F.cswap(i2, pointPrecompZ.ymx_h, pointPrecompZ.ypx_h);
        C1378F.cnegate(i2, pointPrecompZ.xyd);
    }

    private static void pointPrecompute(PointAffine pointAffine, PointExtended[] pointExtendedArr, int i, int i2, PointTemp pointTemp) {
        PointExtended pointExtended = new PointExtended();
        pointExtendedArr[i] = pointExtended;
        pointCopy(pointAffine, pointExtended);
        PointExtended pointExtended2 = new PointExtended();
        PointExtended pointExtended3 = pointExtendedArr[i];
        pointAdd(pointExtended3, pointExtended3, pointExtended2, pointTemp);
        for (int i3 = 1; i3 < i2; i3++) {
            int i4 = i + i3;
            PointExtended pointExtended4 = pointExtendedArr[i4 - 1];
            PointExtended pointExtended5 = new PointExtended();
            pointExtendedArr[i4] = pointExtended5;
            pointAdd(pointExtended4, pointExtended2, pointExtended5, pointTemp);
        }
    }

    private static void pointPrecomputeZ(PointAffine pointAffine, PointPrecompZ[] pointPrecompZArr, int i, PointTemp pointTemp) {
        PointExtended pointExtended = new PointExtended();
        pointCopy(pointAffine, pointExtended);
        PointExtended pointExtended2 = new PointExtended();
        pointAdd(pointExtended, pointExtended, pointExtended2, pointTemp);
        int i2 = 0;
        while (true) {
            PointPrecompZ pointPrecompZ = new PointPrecompZ();
            pointPrecompZArr[i2] = pointPrecompZ;
            pointCopy(pointExtended, pointPrecompZ);
            i2++;
            if (i2 == i) {
                return;
            }
            pointAdd(pointExtended, pointExtended2, pointExtended, pointTemp);
        }
    }

    private static int[] pointPrecomputeZ(PointAffine pointAffine, int i, PointTemp pointTemp) {
        PointExtended pointExtended = new PointExtended();
        pointCopy(pointAffine, pointExtended);
        PointExtended pointExtended2 = new PointExtended();
        pointAdd(pointExtended, pointExtended, pointExtended2, pointTemp);
        PointPrecompZ pointPrecompZ = new PointPrecompZ();
        int[] createTable = C1378F.createTable(i * 4);
        int i2 = 0;
        int i3 = 0;
        while (true) {
            pointCopy(pointExtended, pointPrecompZ);
            C1378F.copy(pointPrecompZ.ymx_h, 0, createTable, i2);
            C1378F.copy(pointPrecompZ.ypx_h, 0, createTable, i2 + 10);
            C1378F.copy(pointPrecompZ.xyd, 0, createTable, i2 + 20);
            C1378F.copy(pointPrecompZ.f1114z, 0, createTable, i2 + 30);
            i2 += 40;
            i3++;
            if (i3 == i) {
                return createTable;
            }
            pointAdd(pointExtended, pointExtended2, pointExtended, pointTemp);
        }
    }

    private static void pointSetNeutral(PointAccum pointAccum) {
        C1378F.zero(pointAccum.f1105x);
        C1378F.one(pointAccum.f1106y);
        C1378F.one(pointAccum.f1107z);
        C1378F.zero(pointAccum.f1103u);
        C1378F.one(pointAccum.f1104v);
    }

    public static void precompute() {
        synchronized (PRECOMP_LOCK) {
            if (PRECOMP_BASE_COMB != null) {
                return;
            }
            PointExtended[] pointExtendedArr = new PointExtended[96];
            PointTemp pointTemp = new PointTemp();
            PointAffine pointAffine = new PointAffine();
            int[] iArr = B_x;
            int i = 0;
            C1378F.copy(iArr, 0, pointAffine.f1108x, 0);
            int[] iArr2 = B_y;
            C1378F.copy(iArr2, 0, pointAffine.f1109y, 0);
            pointPrecompute(pointAffine, pointExtendedArr, 0, 16, pointTemp);
            PointAffine pointAffine2 = new PointAffine();
            C1378F.copy(B128_x, 0, pointAffine2.f1108x, 0);
            C1378F.copy(B128_y, 0, pointAffine2.f1109y, 0);
            pointPrecompute(pointAffine2, pointExtendedArr, 16, 16, pointTemp);
            PointAccum pointAccum = new PointAccum();
            C1378F.copy(iArr, 0, pointAccum.f1105x, 0);
            C1378F.copy(iArr2, 0, pointAccum.f1106y, 0);
            C1378F.one(pointAccum.f1107z);
            C1378F.copy(pointAccum.f1105x, 0, pointAccum.f1103u, 0);
            C1378F.copy(pointAccum.f1106y, 0, pointAccum.f1104v, 0);
            int i2 = 4;
            PointExtended[] pointExtendedArr2 = new PointExtended[4];
            for (int i3 = 0; i3 < 4; i3++) {
                pointExtendedArr2[i3] = new PointExtended();
            }
            PointExtended pointExtended = new PointExtended();
            int i4 = 0;
            int i5 = 32;
            while (i4 < 8) {
                int i6 = i5 + 1;
                PointExtended pointExtended2 = new PointExtended();
                pointExtendedArr[i5] = pointExtended2;
                int i7 = i;
                while (i7 < i2) {
                    if (i7 == 0) {
                        pointCopy(pointAccum, pointExtended2);
                    } else {
                        pointCopy(pointAccum, pointExtended);
                        pointAdd(pointExtended2, pointExtended, pointExtended2, pointTemp);
                    }
                    pointDouble(pointAccum);
                    pointCopy(pointAccum, pointExtendedArr2[i7]);
                    if (i4 + i7 != 10) {
                        for (int i8 = 1; i8 < 8; i8++) {
                            pointDouble(pointAccum);
                        }
                    }
                    i7++;
                    i2 = 4;
                }
                C1378F.negate(pointExtended2.f1111x, pointExtended2.f1111x);
                C1378F.negate(pointExtended2.f1110t, pointExtended2.f1110t);
                i5 = i6;
                for (int i9 = 0; i9 < 3; i9++) {
                    int i10 = 1 << i9;
                    int i11 = 0;
                    while (i11 < i10) {
                        PointExtended pointExtended3 = new PointExtended();
                        pointExtendedArr[i5] = pointExtended3;
                        pointAdd(pointExtendedArr[i5 - i10], pointExtendedArr2[i9], pointExtended3, pointTemp);
                        i11++;
                        i5++;
                    }
                }
                i4++;
                i2 = 4;
                i = 0;
            }
            invertDoubleZs(pointExtendedArr);
            PRECOMP_BASE_WNAF = new PointPrecomp[16];
            for (int i12 = 0; i12 < 16; i12++) {
                PointExtended pointExtended4 = pointExtendedArr[i12];
                PointPrecomp[] pointPrecompArr = PRECOMP_BASE_WNAF;
                PointPrecomp pointPrecomp = new PointPrecomp();
                pointPrecompArr[i12] = pointPrecomp;
                C1378F.mul(pointExtended4.f1111x, pointExtended4.f1113z, pointExtended4.f1111x);
                C1378F.mul(pointExtended4.f1112y, pointExtended4.f1113z, pointExtended4.f1112y);
                C1378F.apm(pointExtended4.f1112y, pointExtended4.f1111x, pointPrecomp.ypx_h, pointPrecomp.ymx_h);
                C1378F.mul(pointExtended4.f1111x, pointExtended4.f1112y, pointPrecomp.xyd);
                C1378F.mul(pointPrecomp.xyd, C_d4, pointPrecomp.xyd);
                C1378F.normalize(pointPrecomp.ymx_h);
                C1378F.normalize(pointPrecomp.ypx_h);
                C1378F.normalize(pointPrecomp.xyd);
            }
            PRECOMP_BASE128_WNAF = new PointPrecomp[16];
            for (int i13 = 0; i13 < 16; i13++) {
                PointExtended pointExtended5 = pointExtendedArr[16 + i13];
                PointPrecomp[] pointPrecompArr2 = PRECOMP_BASE128_WNAF;
                PointPrecomp pointPrecomp2 = new PointPrecomp();
                pointPrecompArr2[i13] = pointPrecomp2;
                C1378F.mul(pointExtended5.f1111x, pointExtended5.f1113z, pointExtended5.f1111x);
                C1378F.mul(pointExtended5.f1112y, pointExtended5.f1113z, pointExtended5.f1112y);
                C1378F.apm(pointExtended5.f1112y, pointExtended5.f1111x, pointPrecomp2.ypx_h, pointPrecomp2.ymx_h);
                C1378F.mul(pointExtended5.f1111x, pointExtended5.f1112y, pointPrecomp2.xyd);
                C1378F.mul(pointPrecomp2.xyd, C_d4, pointPrecomp2.xyd);
                C1378F.normalize(pointPrecomp2.ymx_h);
                C1378F.normalize(pointPrecomp2.ypx_h);
                C1378F.normalize(pointPrecomp2.xyd);
            }
            PRECOMP_BASE_COMB = C1378F.createTable(192);
            PointPrecomp pointPrecomp3 = new PointPrecomp();
            int i14 = 0;
            for (int i15 = 32; i15 < 96; i15++) {
                PointExtended pointExtended6 = pointExtendedArr[i15];
                C1378F.mul(pointExtended6.f1111x, pointExtended6.f1113z, pointExtended6.f1111x);
                C1378F.mul(pointExtended6.f1112y, pointExtended6.f1113z, pointExtended6.f1112y);
                C1378F.apm(pointExtended6.f1112y, pointExtended6.f1111x, pointPrecomp3.ypx_h, pointPrecomp3.ymx_h);
                C1378F.mul(pointExtended6.f1111x, pointExtended6.f1112y, pointPrecomp3.xyd);
                C1378F.mul(pointPrecomp3.xyd, C_d4, pointPrecomp3.xyd);
                C1378F.normalize(pointPrecomp3.ymx_h);
                C1378F.normalize(pointPrecomp3.ypx_h);
                C1378F.normalize(pointPrecomp3.xyd);
                C1378F.copy(pointPrecomp3.ymx_h, 0, PRECOMP_BASE_COMB, i14);
                C1378F.copy(pointPrecomp3.ypx_h, 0, PRECOMP_BASE_COMB, i14 + 10);
                C1378F.copy(pointPrecomp3.xyd, 0, PRECOMP_BASE_COMB, i14 + 20);
                i14 += 30;
            }
        }
    }

    private static void pruneScalar(byte[] bArr, int i, byte[] bArr2) {
        System.arraycopy(bArr, i, bArr2, 0, 32);
        bArr2[0] = (byte) (bArr2[0] & 248);
        byte b = (byte) (bArr2[31] & ByteCompanionObject.MAX_VALUE);
        bArr2[31] = b;
        bArr2[31] = (byte) (b | 64);
    }

    private static void scalarMult(byte[] bArr, PointAffine pointAffine, PointAccum pointAccum) {
        int[] iArr = new int[8];
        Scalar25519.decode(bArr, iArr);
        Scalar25519.toSignedDigits(256, iArr);
        PointPrecompZ pointPrecompZ = new PointPrecompZ();
        PointTemp pointTemp = new PointTemp();
        int[] pointPrecomputeZ = pointPrecomputeZ(pointAffine, 8, pointTemp);
        pointSetNeutral(pointAccum);
        int i = 63;
        while (true) {
            pointLookupZ(iArr, i, pointPrecomputeZ, pointPrecompZ);
            pointAdd(pointPrecompZ, pointAccum, pointTemp);
            i--;
            if (i < 0) {
                return;
            }
            for (int i2 = 0; i2 < 4; i2++) {
                pointDouble(pointAccum);
            }
        }
    }

    private static void scalarMultBase(byte[] bArr, PointAccum pointAccum) {
        precompute();
        int[] iArr = new int[8];
        Scalar25519.decode(bArr, iArr);
        Scalar25519.toSignedDigits(256, iArr);
        groupCombBits(iArr);
        PointPrecomp pointPrecomp = new PointPrecomp();
        PointTemp pointTemp = new PointTemp();
        pointSetNeutral(pointAccum);
        int i = 28;
        int i2 = 0;
        while (true) {
            int i3 = 0;
            while (i3 < 8) {
                int i4 = iArr[i3] >>> i;
                int i5 = (i4 >>> 3) & 1;
                pointLookup(i3, (i4 ^ (-i5)) & 7, pointPrecomp);
                int i6 = i2 ^ i5;
                C1378F.cnegate(i6, pointAccum.f1105x);
                C1378F.cnegate(i6, pointAccum.f1103u);
                pointAdd(pointPrecomp, pointAccum, pointTemp);
                i3++;
                i2 = i5;
            }
            i -= 4;
            if (i < 0) {
                C1378F.cnegate(i2, pointAccum.f1105x);
                C1378F.cnegate(i2, pointAccum.f1103u);
                return;
            }
            pointDouble(pointAccum);
        }
    }

    private static void scalarMultBaseEncoded(byte[] bArr, byte[] bArr2, int i) {
        PointAccum pointAccum = new PointAccum();
        scalarMultBase(bArr, pointAccum);
        if (encodeResult(pointAccum, bArr2, i) == 0) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseYZ(X25519.Friend friend, byte[] bArr, int i, int[] iArr, int[] iArr2) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by X25519");
        }
        byte[] bArr2 = new byte[32];
        pruneScalar(bArr, i, bArr2);
        PointAccum pointAccum = new PointAccum();
        scalarMultBase(bArr2, pointAccum);
        if (checkPoint(pointAccum) == 0) {
            throw new IllegalStateException();
        }
        C1378F.copy(pointAccum.f1106y, 0, iArr, 0);
        C1378F.copy(pointAccum.f1107z, 0, iArr2, 0);
    }

    private static void scalarMultOrderVar(PointAffine pointAffine, PointAccum pointAccum) {
        byte[] bArr = new byte[253];
        Scalar25519.getOrderWnafVar(4, bArr);
        PointPrecompZ[] pointPrecompZArr = new PointPrecompZ[4];
        PointTemp pointTemp = new PointTemp();
        pointPrecomputeZ(pointAffine, pointPrecompZArr, 4, pointTemp);
        pointSetNeutral(pointAccum);
        int i = 252;
        while (true) {
            byte b = bArr[i];
            if (b != 0) {
                pointAddVar(b < 0, pointPrecompZArr[(b >> 1) ^ (b >> 31)], pointAccum, pointTemp);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointAccum);
        }
    }

    private static void scalarMultStraus128Var(int[] iArr, int[] iArr2, PointAffine pointAffine, int[] iArr3, PointAffine pointAffine2, PointAccum pointAccum) {
        int i;
        precompute();
        byte[] bArr = new byte[256];
        int i2 = 128;
        byte[] bArr2 = new byte[128];
        byte[] bArr3 = new byte[128];
        Wnaf.getSignedVar(iArr, 6, bArr);
        Wnaf.getSignedVar(iArr2, 4, bArr2);
        Wnaf.getSignedVar(iArr3, 4, bArr3);
        PointPrecompZ[] pointPrecompZArr = new PointPrecompZ[4];
        PointPrecompZ[] pointPrecompZArr2 = new PointPrecompZ[4];
        PointTemp pointTemp = new PointTemp();
        pointPrecomputeZ(pointAffine, pointPrecompZArr, 4, pointTemp);
        pointPrecomputeZ(pointAffine2, pointPrecompZArr2, 4, pointTemp);
        pointSetNeutral(pointAccum);
        while (true) {
            i = i2 - 1;
            if (i < 0 || (bArr[i] | bArr[i2 + 127] | bArr2[i] | bArr3[i]) != 0) {
                break;
            }
            i2 = i;
        }
        while (i >= 0) {
            byte b = bArr[i];
            if (b != 0) {
                pointAddVar(b < 0, PRECOMP_BASE_WNAF[(b >> 1) ^ (b >> 31)], pointAccum, pointTemp);
            }
            byte b2 = bArr[i + 128];
            if (b2 != 0) {
                pointAddVar(b2 < 0, PRECOMP_BASE128_WNAF[(b2 >> 1) ^ (b2 >> 31)], pointAccum, pointTemp);
            }
            byte b3 = bArr2[i];
            if (b3 != 0) {
                pointAddVar(b3 < 0, pointPrecompZArr[(b3 >> 1) ^ (b3 >> 31)], pointAccum, pointTemp);
            }
            byte b4 = bArr3[i];
            if (b4 != 0) {
                pointAddVar(b4 < 0, pointPrecompZArr2[(b4 >> 1) ^ (b4 >> 31)], pointAccum, pointTemp);
            }
            pointDouble(pointAccum);
            i--;
        }
        pointDouble(pointAccum);
        pointDouble(pointAccum);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        implSign(bArr, i, null, (byte) 0, bArr2, i2, i3, bArr3, i4);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4, byte[] bArr4, int i5) {
        implSign(bArr, i, bArr2, i2, null, (byte) 0, bArr3, i3, i4, bArr4, i5);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4, byte[] bArr5, int i5) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4, bArr5, i5);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        implSign(bArr, i, bArr2, (byte) 0, bArr3, i2, i3, bArr4, i4);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Digest digest, byte[] bArr4, int i3) {
        byte[] bArr5 = new byte[64];
        if (64 != digest.doFinal(bArr5, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr5, 0, 64, bArr4, i3);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, byte[] bArr5, int i4) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64, bArr5, i4);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, Digest digest, byte[] bArr3, int i2) {
        byte[] bArr4 = new byte[64];
        if (64 != digest.doFinal(bArr4, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, (byte) 1, bArr4, 0, 64, bArr3, i2);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, byte[] bArr4, int i3) {
        implSign(bArr, i, bArr2, (byte) 1, bArr3, i2, 64, bArr4, i3);
    }

    public static boolean validatePublicKeyFull(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 32);
        if (checkPointFullVar(copy)) {
            PointAffine pointAffine = new PointAffine();
            if (decodePointVar(copy, false, pointAffine)) {
                return checkPointOrderVar(pointAffine);
            }
            return false;
        }
        return false;
    }

    public static PublicPoint validatePublicKeyFullExport(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 32);
        if (checkPointFullVar(copy)) {
            PointAffine pointAffine = new PointAffine();
            if (decodePointVar(copy, false, pointAffine) && checkPointOrderVar(pointAffine)) {
                return exportPoint(pointAffine);
            }
            return null;
        }
        return null;
    }

    public static boolean validatePublicKeyPartial(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 32);
        if (checkPointFullVar(copy)) {
            return decodePointVar(copy, false, new PointAffine());
        }
        return false;
    }

    public static PublicPoint validatePublicKeyPartialExport(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 32);
        if (checkPointFullVar(copy)) {
            PointAffine pointAffine = new PointAffine();
            if (decodePointVar(copy, false, pointAffine)) {
                return exportPoint(pointAffine);
            }
            return null;
        }
        return null;
    }

    public static boolean verify(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, int i2, int i3) {
        return implVerify(bArr, i, publicPoint, null, (byte) 0, bArr2, i2, i3);
    }

    public static boolean verify(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte[] bArr3, int i2, int i3) {
        return implVerify(bArr, i, publicPoint, bArr2, (byte) 0, bArr3, i2, i3);
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, null, (byte) 0, bArr3, i3, i4);
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, Digest digest) {
        byte[] bArr3 = new byte[64];
        if (64 == digest.doFinal(bArr3, 0)) {
            return implVerify(bArr, i, publicPoint, bArr2, (byte) 1, bArr3, 0, 64);
        }
        throw new IllegalArgumentException("ph");
    }

    public static boolean verifyPrehash(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte[] bArr3, int i2) {
        return implVerify(bArr, i, publicPoint, bArr2, (byte) 1, bArr3, i2, 64);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Digest digest) {
        byte[] bArr4 = new byte[64];
        if (64 == digest.doFinal(bArr4, 0)) {
            return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, 0, 64);
        }
        throw new IllegalArgumentException("ph");
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64);
    }
}