package org.bouncycastle.math.p016ec.rfc8032;

import java.security.SecureRandom;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.math.p016ec.rfc7748.X448;
import org.bouncycastle.math.p016ec.rfc7748.X448Field;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.tls.CipherSuite;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448 */
/* loaded from: classes2.dex */
public abstract class Ed448 {
    private static final int COORD_INTS = 14;
    private static final int C_d = 39081;
    private static final int POINT_BYTES = 57;
    private static final int PRECOMP_BLOCKS = 5;
    private static final int PRECOMP_MASK = 15;
    private static final int PRECOMP_POINTS = 16;
    private static final int PRECOMP_RANGE = 450;
    private static final int PRECOMP_SPACING = 18;
    private static final int PRECOMP_TEETH = 5;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 57;
    private static final int SCALAR_BYTES = 57;
    private static final int SCALAR_INTS = 14;
    public static final int SECRET_KEY_SIZE = 57;
    public static final int SIGNATURE_SIZE = 114;
    private static final int WNAF_WIDTH_225 = 5;
    private static final int WNAF_WIDTH_BASE = 7;
    private static final byte[] DOM4_PREFIX = {83, 105, 103, 69, 100, 52, 52, 56};

    /* renamed from: P */
    private static final int[] f1117P = {-1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -1, -1, -1, -1};
    private static final int[] B_x = {118276190, 40534716, 9670182, 135141552, 85017403, 259173222, 68333082, 171784774, 174973732, 15824510, 73756743, 57518561, 94773951, 248652241, 107736333, 82941708};
    private static final int[] B_y = {36764180, 8885695, 130592152, 20104429, 163904957, 30304195, 121295871, 5901357, 125344798, 171541512, 175338348, 209069246, 3626697, 38307682, 24032956, 110359655};
    private static final int[] B225_x = {110141154, 30892124, 160820362, 264558960, 217232225, 47722141, 19029845, 8326902, 183409749, 170134547, 90340180, 222600478, 61097333, 7431335, 198491505, 102372861};
    private static final int[] B225_y = {221945828, 50763449, 132637478, 109250759, 216053960, 61612587, 50649998, 138339097, 98949899, 248139835, 186410297, 126520782, 47339196, 78164062, 198835543, 169622712};
    private static final Object PRECOMP_LOCK = new Object();
    private static PointAffine[] PRECOMP_BASE_WNAF = null;
    private static PointAffine[] PRECOMP_BASE225_WNAF = null;
    private static int[] PRECOMP_BASE_COMB = null;

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$Algorithm */
    /* loaded from: classes2.dex */
    public static final class Algorithm {
        public static final int Ed448 = 0;
        public static final int Ed448ph = 1;
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$F */
    /* loaded from: classes2.dex */
    private static class C1380F extends X448Field {
        private C1380F() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PointAffine */
    /* loaded from: classes2.dex */
    public static class PointAffine {

        /* renamed from: x */
        int[] f1118x;

        /* renamed from: y */
        int[] f1119y;

        private PointAffine() {
            this.f1118x = C1380F.create();
            this.f1119y = C1380F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PointProjective */
    /* loaded from: classes2.dex */
    public static class PointProjective {

        /* renamed from: x */
        int[] f1120x;

        /* renamed from: y */
        int[] f1121y;

        /* renamed from: z */
        int[] f1122z;

        private PointProjective() {
            this.f1120x = C1380F.create();
            this.f1121y = C1380F.create();
            this.f1122z = C1380F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PointTemp */
    /* loaded from: classes2.dex */
    public static class PointTemp {

        /* renamed from: r0 */
        int[] f1123r0;

        /* renamed from: r1 */
        int[] f1124r1;

        /* renamed from: r2 */
        int[] f1125r2;

        /* renamed from: r3 */
        int[] f1126r3;

        /* renamed from: r4 */
        int[] f1127r4;

        /* renamed from: r5 */
        int[] f1128r5;

        /* renamed from: r6 */
        int[] f1129r6;

        /* renamed from: r7 */
        int[] f1130r7;

        private PointTemp() {
            this.f1123r0 = C1380F.create();
            this.f1124r1 = C1380F.create();
            this.f1125r2 = C1380F.create();
            this.f1126r3 = C1380F.create();
            this.f1127r4 = C1380F.create();
            this.f1128r5 = C1380F.create();
            this.f1129r6 = C1380F.create();
            this.f1130r7 = C1380F.create();
        }
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed448$PublicPoint */
    /* loaded from: classes2.dex */
    public static final class PublicPoint {
        final int[] data;

        PublicPoint(int[] iArr) {
            this.data = iArr;
        }
    }

    private static byte[] calculateS(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int[] iArr = new int[28];
        Scalar448.decode(bArr, iArr);
        int[] iArr2 = new int[14];
        Scalar448.decode(bArr2, iArr2);
        int[] iArr3 = new int[14];
        Scalar448.decode(bArr3, iArr3);
        Nat.mulAddTo(14, iArr2, iArr3, iArr);
        byte[] bArr4 = new byte[114];
        Codec.encode32(iArr, 0, 28, bArr4, 0);
        return Scalar448.reduce912(bArr4);
    }

    private static boolean checkContextVar(byte[] bArr) {
        return bArr != null && bArr.length < 256;
    }

    private static int checkPoint(PointAffine pointAffine) {
        int[] create = C1380F.create();
        int[] create2 = C1380F.create();
        int[] create3 = C1380F.create();
        C1380F.sqr(pointAffine.f1118x, create2);
        C1380F.sqr(pointAffine.f1119y, create3);
        C1380F.mul(create2, create3, create);
        C1380F.add(create2, create3, create2);
        C1380F.mul(create, (int) C_d, create);
        C1380F.subOne(create);
        C1380F.add(create, create2, create);
        C1380F.normalize(create);
        C1380F.normalize(create3);
        return C1380F.isZero(create) & (~C1380F.isZero(create3));
    }

    private static int checkPoint(PointProjective pointProjective) {
        int[] create = C1380F.create();
        int[] create2 = C1380F.create();
        int[] create3 = C1380F.create();
        int[] create4 = C1380F.create();
        C1380F.sqr(pointProjective.f1120x, create2);
        C1380F.sqr(pointProjective.f1121y, create3);
        C1380F.sqr(pointProjective.f1122z, create4);
        C1380F.mul(create2, create3, create);
        C1380F.add(create2, create3, create2);
        C1380F.mul(create2, create4, create2);
        C1380F.sqr(create4, create4);
        C1380F.mul(create, (int) C_d, create);
        C1380F.sub(create, create4, create);
        C1380F.add(create, create2, create);
        C1380F.normalize(create);
        C1380F.normalize(create3);
        C1380F.normalize(create4);
        return C1380F.isZero(create) & (~C1380F.isZero(create3)) & (~C1380F.isZero(create4));
    }

    private static boolean checkPointFullVar(byte[] bArr) {
        if ((bArr[56] & ByteCompanionObject.MAX_VALUE) != 0) {
            return false;
        }
        int decode32 = Codec.decode32(bArr, 52);
        int i = f1117P[13] ^ decode32;
        for (int i2 = 12; i2 > 0; i2--) {
            int decode322 = Codec.decode32(bArr, i2 * 4);
            if (i == 0 && decode322 - 2147483648 > f1117P[i2] - 2147483648) {
                return false;
            }
            decode32 |= decode322;
            i |= f1117P[i2] ^ decode322;
        }
        int decode323 = Codec.decode32(bArr, 0);
        if (decode32 != 0 || decode323 - 2147483648 > -2147483647) {
            return i != 0 || decode323 + Integer.MIN_VALUE < f1117P[0] - (-2147483647);
        }
        return false;
    }

    private static boolean checkPointOrderVar(PointAffine pointAffine) {
        PointProjective pointProjective = new PointProjective();
        scalarMultOrderVar(pointAffine, pointProjective);
        return normalizeToNeutralElementVar(pointProjective);
    }

    private static boolean checkPointVar(byte[] bArr) {
        if ((bArr[56] & ByteCompanionObject.MAX_VALUE) != 0) {
            return false;
        }
        int decode32 = Codec.decode32(bArr, 52);
        int[] iArr = f1117P;
        if (decode32 != iArr[13]) {
            return true;
        }
        int[] iArr2 = new int[14];
        Codec.decode32(bArr, 0, iArr2, 0, 14);
        return !Nat.gte(14, iArr2, iArr);
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

    private static boolean decodePointVar(byte[] bArr, boolean z, PointAffine pointAffine) {
        int i = (bArr[56] & ByteCompanionObject.MIN_VALUE) >>> 7;
        C1380F.decode(bArr, pointAffine.f1119y);
        int[] create = C1380F.create();
        int[] create2 = C1380F.create();
        C1380F.sqr(pointAffine.f1119y, create);
        C1380F.mul(create, (int) C_d, create2);
        C1380F.negate(create, create);
        C1380F.addOne(create);
        C1380F.addOne(create2);
        if (C1380F.sqrtRatioVar(create, create2, pointAffine.f1118x)) {
            C1380F.normalize(pointAffine.f1118x);
            if (i == 1 && C1380F.isZeroVar(pointAffine.f1118x)) {
                return false;
            }
            if (z ^ (i != (pointAffine.f1118x[0] & 1))) {
                C1380F.negate(pointAffine.f1118x, pointAffine.f1118x);
                C1380F.normalize(pointAffine.f1118x);
            }
            return true;
        }
        return false;
    }

    private static void dom4(Xof xof, byte b, byte[] bArr) {
        byte[] bArr2 = DOM4_PREFIX;
        int length = bArr2.length;
        int i = length + 2;
        int length2 = bArr.length + i;
        byte[] bArr3 = new byte[length2];
        System.arraycopy(bArr2, 0, bArr3, 0, length);
        bArr3[length] = b;
        bArr3[length + 1] = (byte) bArr.length;
        System.arraycopy(bArr, 0, bArr3, i, bArr.length);
        xof.update(bArr3, 0, length2);
    }

    private static void encodePoint(PointAffine pointAffine, byte[] bArr, int i) {
        C1380F.encode(pointAffine.f1119y, bArr, i);
        bArr[i + 56] = (byte) ((pointAffine.f1118x[0] & 1) << 7);
    }

    public static void encodePublicPoint(PublicPoint publicPoint, byte[] bArr, int i) {
        C1380F.encode(publicPoint.data, 16, bArr, i);
        bArr[i + 56] = (byte) ((publicPoint.data[0] & 1) << 7);
    }

    private static int encodeResult(PointProjective pointProjective, byte[] bArr, int i) {
        PointAffine pointAffine = new PointAffine();
        normalizeToAffine(pointProjective, pointAffine);
        int checkPoint = checkPoint(pointAffine);
        encodePoint(pointAffine, bArr, i);
        return checkPoint;
    }

    private static PublicPoint exportPoint(PointAffine pointAffine) {
        int[] iArr = new int[32];
        C1380F.copy(pointAffine.f1118x, 0, iArr, 0);
        C1380F.copy(pointAffine.f1119y, 0, iArr, 16);
        return new PublicPoint(iArr);
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        if (bArr.length != 57) {
            throw new IllegalArgumentException("k");
        }
        secureRandom.nextBytes(bArr);
    }

    public static PublicPoint generatePublicKey(byte[] bArr, int i) {
        Xof createXof = createXof();
        byte[] bArr2 = new byte[114];
        createXof.update(bArr, i, 57);
        createXof.doFinal(bArr2, 0, 114);
        byte[] bArr3 = new byte[57];
        pruneScalar(bArr2, 0, bArr3);
        PointProjective pointProjective = new PointProjective();
        scalarMultBase(bArr3, pointProjective);
        PointAffine pointAffine = new PointAffine();
        normalizeToAffine(pointProjective, pointAffine);
        if (checkPoint(pointAffine) != 0) {
            return exportPoint(pointAffine);
        }
        throw new IllegalStateException();
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        Xof createXof = createXof();
        byte[] bArr3 = new byte[114];
        createXof.update(bArr, i, 57);
        createXof.doFinal(bArr3, 0, 114);
        byte[] bArr4 = new byte[57];
        pruneScalar(bArr3, 0, bArr4);
        scalarMultBaseEncoded(bArr4, bArr2, i2);
    }

    private static int getWindow4(int[] iArr, int i) {
        return (iArr[i >>> 3] >>> ((i & 7) << 2)) & 15;
    }

    private static void implSign(Xof xof, byte[] bArr, byte[] bArr2, byte[] bArr3, int i, byte[] bArr4, byte b, byte[] bArr5, int i2, int i3, byte[] bArr6, int i4) {
        dom4(xof, b, bArr4);
        xof.update(bArr, 57, 57);
        xof.update(bArr5, i2, i3);
        xof.doFinal(bArr, 0, bArr.length);
        byte[] reduce912 = Scalar448.reduce912(bArr);
        byte[] bArr7 = new byte[57];
        scalarMultBaseEncoded(reduce912, bArr7, 0);
        dom4(xof, b, bArr4);
        xof.update(bArr7, 0, 57);
        xof.update(bArr3, i, 57);
        xof.update(bArr5, i2, i3);
        xof.doFinal(bArr, 0, bArr.length);
        byte[] calculateS = calculateS(reduce912, Scalar448.reduce912(bArr), bArr2);
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
        createXof.doFinal(bArr5, 0, 114);
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
        createXof.doFinal(bArr6, 0, 114);
        byte[] bArr7 = new byte[57];
        pruneScalar(bArr6, 0, bArr7);
        implSign(createXof, bArr6, bArr7, bArr2, i2, bArr3, b, bArr4, i3, i4, bArr5, i5);
    }

    private static boolean implVerify(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte b, byte[] bArr3, int i2, int i3) {
        if (checkContextVar(bArr2)) {
            byte[] copy = copy(bArr, i, 57);
            byte[] copy2 = copy(bArr, i + 57, 57);
            if (checkPointVar(copy)) {
                int[] iArr = new int[14];
                if (Scalar448.checkVar(copy2, iArr)) {
                    PointAffine pointAffine = new PointAffine();
                    if (decodePointVar(copy, true, pointAffine)) {
                        PointAffine pointAffine2 = new PointAffine();
                        C1380F.negate(publicPoint.data, pointAffine2.f1118x);
                        C1380F.copy(publicPoint.data, 16, pointAffine2.f1119y, 0);
                        byte[] bArr4 = new byte[57];
                        encodePublicPoint(publicPoint, bArr4, 0);
                        Xof createXof = createXof();
                        byte[] bArr5 = new byte[114];
                        dom4(createXof, b, bArr2);
                        createXof.update(copy, 0, 57);
                        createXof.update(bArr4, 0, 57);
                        createXof.update(bArr3, i2, i3);
                        createXof.doFinal(bArr5, 0, 114);
                        int[] iArr2 = new int[14];
                        Scalar448.decode(Scalar448.reduce912(bArr5), iArr2);
                        int[] iArr3 = new int[8];
                        int[] iArr4 = new int[8];
                        if (Scalar448.reduceBasisVar(iArr2, iArr3, iArr4)) {
                            Scalar448.multiply225Var(iArr, iArr4, iArr);
                            PointProjective pointProjective = new PointProjective();
                            scalarMultStraus225Var(iArr, iArr3, pointAffine2, iArr4, pointAffine, pointProjective);
                            return normalizeToNeutralElementVar(pointProjective);
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
        if (checkContextVar(bArr3)) {
            byte[] copy = copy(bArr, i, 57);
            byte[] copy2 = copy(bArr, i + 57, 57);
            byte[] copy3 = copy(bArr2, i2, 57);
            if (checkPointVar(copy)) {
                int[] iArr = new int[14];
                if (Scalar448.checkVar(copy2, iArr) && checkPointFullVar(copy3)) {
                    PointAffine pointAffine = new PointAffine();
                    if (decodePointVar(copy, true, pointAffine)) {
                        PointAffine pointAffine2 = new PointAffine();
                        if (decodePointVar(copy3, true, pointAffine2)) {
                            Xof createXof = createXof();
                            byte[] bArr5 = new byte[114];
                            dom4(createXof, b, bArr3);
                            createXof.update(copy, 0, 57);
                            createXof.update(copy3, 0, 57);
                            createXof.update(bArr4, i3, i4);
                            createXof.doFinal(bArr5, 0, 114);
                            int[] iArr2 = new int[14];
                            Scalar448.decode(Scalar448.reduce912(bArr5), iArr2);
                            int[] iArr3 = new int[8];
                            int[] iArr4 = new int[8];
                            if (Scalar448.reduceBasisVar(iArr2, iArr3, iArr4)) {
                                Scalar448.multiply225Var(iArr, iArr4, iArr);
                                PointProjective pointProjective = new PointProjective();
                                scalarMultStraus225Var(iArr, iArr3, pointAffine2, iArr4, pointAffine, pointProjective);
                                return normalizeToNeutralElementVar(pointProjective);
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

    private static void invertZs(PointProjective[] pointProjectiveArr) {
        int length = pointProjectiveArr.length;
        int[] createTable = C1380F.createTable(length);
        int[] create = C1380F.create();
        C1380F.copy(pointProjectiveArr[0].f1122z, 0, create, 0);
        C1380F.copy(create, 0, createTable, 0);
        int i = 0;
        while (true) {
            int i2 = i + 1;
            if (i2 >= length) {
                break;
            }
            C1380F.mul(create, pointProjectiveArr[i2].f1122z, create);
            C1380F.copy(create, 0, createTable, i2 * 16);
            i = i2;
        }
        C1380F.invVar(create, create);
        int[] create2 = C1380F.create();
        while (i > 0) {
            int i3 = i - 1;
            C1380F.copy(createTable, i3 * 16, create2, 0);
            C1380F.mul(create2, create, create2);
            C1380F.mul(create, pointProjectiveArr[i].f1122z, create);
            C1380F.copy(create2, 0, pointProjectiveArr[i].f1122z, 0);
            i = i3;
        }
        C1380F.copy(create, 0, pointProjectiveArr[0].f1122z, 0);
    }

    private static void normalizeToAffine(PointProjective pointProjective, PointAffine pointAffine) {
        C1380F.inv(pointProjective.f1122z, pointAffine.f1119y);
        C1380F.mul(pointAffine.f1119y, pointProjective.f1120x, pointAffine.f1118x);
        C1380F.mul(pointAffine.f1119y, pointProjective.f1121y, pointAffine.f1119y);
        C1380F.normalize(pointAffine.f1118x);
        C1380F.normalize(pointAffine.f1119y);
    }

    private static boolean normalizeToNeutralElementVar(PointProjective pointProjective) {
        C1380F.normalize(pointProjective.f1120x);
        C1380F.normalize(pointProjective.f1121y);
        C1380F.normalize(pointProjective.f1122z);
        return C1380F.isZeroVar(pointProjective.f1120x) && !C1380F.isZeroVar(pointProjective.f1121y) && C1380F.areEqualVar(pointProjective.f1121y, pointProjective.f1122z);
    }

    private static void pointAdd(PointAffine pointAffine, PointProjective pointProjective, PointTemp pointTemp) {
        int[] iArr = pointTemp.f1124r1;
        int[] iArr2 = pointTemp.f1125r2;
        int[] iArr3 = pointTemp.f1126r3;
        int[] iArr4 = pointTemp.f1127r4;
        int[] iArr5 = pointTemp.f1128r5;
        int[] iArr6 = pointTemp.f1129r6;
        int[] iArr7 = pointTemp.f1130r7;
        C1380F.sqr(pointProjective.f1122z, iArr);
        C1380F.mul(pointAffine.f1118x, pointProjective.f1120x, iArr2);
        C1380F.mul(pointAffine.f1119y, pointProjective.f1121y, iArr3);
        C1380F.mul(iArr2, iArr3, iArr4);
        C1380F.mul(iArr4, (int) C_d, iArr4);
        C1380F.add(iArr, iArr4, iArr5);
        C1380F.sub(iArr, iArr4, iArr6);
        C1380F.add(pointAffine.f1119y, pointAffine.f1118x, iArr7);
        C1380F.add(pointProjective.f1121y, pointProjective.f1120x, iArr4);
        C1380F.mul(iArr7, iArr4, iArr7);
        C1380F.add(iArr3, iArr2, iArr);
        C1380F.sub(iArr3, iArr2, iArr4);
        C1380F.carry(iArr);
        C1380F.sub(iArr7, iArr, iArr7);
        C1380F.mul(iArr7, pointProjective.f1122z, iArr7);
        C1380F.mul(iArr4, pointProjective.f1122z, iArr4);
        C1380F.mul(iArr5, iArr7, pointProjective.f1120x);
        C1380F.mul(iArr4, iArr6, pointProjective.f1121y);
        C1380F.mul(iArr5, iArr6, pointProjective.f1122z);
    }

    private static void pointAdd(PointProjective pointProjective, PointProjective pointProjective2, PointTemp pointTemp) {
        int[] iArr = pointTemp.f1123r0;
        int[] iArr2 = pointTemp.f1124r1;
        int[] iArr3 = pointTemp.f1125r2;
        int[] iArr4 = pointTemp.f1126r3;
        int[] iArr5 = pointTemp.f1127r4;
        int[] iArr6 = pointTemp.f1128r5;
        int[] iArr7 = pointTemp.f1129r6;
        int[] iArr8 = pointTemp.f1130r7;
        C1380F.mul(pointProjective.f1122z, pointProjective2.f1122z, iArr);
        C1380F.sqr(iArr, iArr2);
        C1380F.mul(pointProjective.f1120x, pointProjective2.f1120x, iArr3);
        C1380F.mul(pointProjective.f1121y, pointProjective2.f1121y, iArr4);
        C1380F.mul(iArr3, iArr4, iArr5);
        C1380F.mul(iArr5, (int) C_d, iArr5);
        C1380F.add(iArr2, iArr5, iArr6);
        C1380F.sub(iArr2, iArr5, iArr7);
        C1380F.add(pointProjective.f1121y, pointProjective.f1120x, iArr8);
        C1380F.add(pointProjective2.f1121y, pointProjective2.f1120x, iArr5);
        C1380F.mul(iArr8, iArr5, iArr8);
        C1380F.add(iArr4, iArr3, iArr2);
        C1380F.sub(iArr4, iArr3, iArr5);
        C1380F.carry(iArr2);
        C1380F.sub(iArr8, iArr2, iArr8);
        C1380F.mul(iArr8, iArr, iArr8);
        C1380F.mul(iArr5, iArr, iArr5);
        C1380F.mul(iArr6, iArr8, pointProjective2.f1120x);
        C1380F.mul(iArr5, iArr7, pointProjective2.f1121y);
        C1380F.mul(iArr6, iArr7, pointProjective2.f1122z);
    }

    private static void pointAddVar(boolean z, PointAffine pointAffine, PointProjective pointProjective, PointTemp pointTemp) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        int[] iArr5 = pointTemp.f1124r1;
        int[] iArr6 = pointTemp.f1125r2;
        int[] iArr7 = pointTemp.f1126r3;
        int[] iArr8 = pointTemp.f1127r4;
        int[] iArr9 = pointTemp.f1128r5;
        int[] iArr10 = pointTemp.f1129r6;
        int[] iArr11 = pointTemp.f1130r7;
        if (z) {
            C1380F.sub(pointAffine.f1119y, pointAffine.f1118x, iArr11);
            iArr2 = iArr5;
            iArr = iArr8;
            iArr4 = iArr9;
            iArr3 = iArr10;
        } else {
            C1380F.add(pointAffine.f1119y, pointAffine.f1118x, iArr11);
            iArr = iArr5;
            iArr2 = iArr8;
            iArr3 = iArr9;
            iArr4 = iArr10;
        }
        C1380F.sqr(pointProjective.f1122z, iArr5);
        C1380F.mul(pointAffine.f1118x, pointProjective.f1120x, iArr6);
        C1380F.mul(pointAffine.f1119y, pointProjective.f1121y, iArr7);
        C1380F.mul(iArr6, iArr7, iArr8);
        C1380F.mul(iArr8, (int) C_d, iArr8);
        C1380F.add(iArr5, iArr8, iArr3);
        C1380F.sub(iArr5, iArr8, iArr4);
        C1380F.add(pointProjective.f1121y, pointProjective.f1120x, iArr8);
        C1380F.mul(iArr11, iArr8, iArr11);
        C1380F.add(iArr7, iArr6, iArr);
        C1380F.sub(iArr7, iArr6, iArr2);
        C1380F.carry(iArr);
        C1380F.sub(iArr11, iArr5, iArr11);
        C1380F.mul(iArr11, pointProjective.f1122z, iArr11);
        C1380F.mul(iArr8, pointProjective.f1122z, iArr8);
        C1380F.mul(iArr9, iArr11, pointProjective.f1120x);
        C1380F.mul(iArr8, iArr10, pointProjective.f1121y);
        C1380F.mul(iArr9, iArr10, pointProjective.f1122z);
    }

    private static void pointAddVar(boolean z, PointProjective pointProjective, PointProjective pointProjective2, PointTemp pointTemp) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        int[] iArr5 = pointTemp.f1123r0;
        int[] iArr6 = pointTemp.f1124r1;
        int[] iArr7 = pointTemp.f1125r2;
        int[] iArr8 = pointTemp.f1126r3;
        int[] iArr9 = pointTemp.f1127r4;
        int[] iArr10 = pointTemp.f1128r5;
        int[] iArr11 = pointTemp.f1129r6;
        int[] iArr12 = pointTemp.f1130r7;
        if (z) {
            C1380F.sub(pointProjective.f1121y, pointProjective.f1120x, iArr12);
            iArr2 = iArr6;
            iArr = iArr9;
            iArr4 = iArr10;
            iArr3 = iArr11;
        } else {
            C1380F.add(pointProjective.f1121y, pointProjective.f1120x, iArr12);
            iArr = iArr6;
            iArr2 = iArr9;
            iArr3 = iArr10;
            iArr4 = iArr11;
        }
        C1380F.mul(pointProjective.f1122z, pointProjective2.f1122z, iArr5);
        C1380F.sqr(iArr5, iArr6);
        C1380F.mul(pointProjective.f1120x, pointProjective2.f1120x, iArr7);
        C1380F.mul(pointProjective.f1121y, pointProjective2.f1121y, iArr8);
        C1380F.mul(iArr7, iArr8, iArr9);
        C1380F.mul(iArr9, (int) C_d, iArr9);
        C1380F.add(iArr6, iArr9, iArr3);
        C1380F.sub(iArr6, iArr9, iArr4);
        C1380F.add(pointProjective2.f1121y, pointProjective2.f1120x, iArr9);
        C1380F.mul(iArr12, iArr9, iArr12);
        C1380F.add(iArr8, iArr7, iArr);
        C1380F.sub(iArr8, iArr7, iArr2);
        C1380F.carry(iArr);
        C1380F.sub(iArr12, iArr6, iArr12);
        C1380F.mul(iArr12, iArr5, iArr12);
        C1380F.mul(iArr9, iArr5, iArr9);
        C1380F.mul(iArr10, iArr12, pointProjective2.f1120x);
        C1380F.mul(iArr9, iArr11, pointProjective2.f1121y);
        C1380F.mul(iArr10, iArr11, pointProjective2.f1122z);
    }

    private static void pointCopy(PointAffine pointAffine, PointProjective pointProjective) {
        C1380F.copy(pointAffine.f1118x, 0, pointProjective.f1120x, 0);
        C1380F.copy(pointAffine.f1119y, 0, pointProjective.f1121y, 0);
        C1380F.one(pointProjective.f1122z);
    }

    private static void pointCopy(PointProjective pointProjective, PointProjective pointProjective2) {
        C1380F.copy(pointProjective.f1120x, 0, pointProjective2.f1120x, 0);
        C1380F.copy(pointProjective.f1121y, 0, pointProjective2.f1121y, 0);
        C1380F.copy(pointProjective.f1122z, 0, pointProjective2.f1122z, 0);
    }

    private static void pointDouble(PointProjective pointProjective, PointTemp pointTemp) {
        int[] iArr = pointTemp.f1124r1;
        int[] iArr2 = pointTemp.f1125r2;
        int[] iArr3 = pointTemp.f1126r3;
        int[] iArr4 = pointTemp.f1127r4;
        int[] iArr5 = pointTemp.f1130r7;
        int[] iArr6 = pointTemp.f1123r0;
        C1380F.add(pointProjective.f1120x, pointProjective.f1121y, iArr);
        C1380F.sqr(iArr, iArr);
        C1380F.sqr(pointProjective.f1120x, iArr2);
        C1380F.sqr(pointProjective.f1121y, iArr3);
        C1380F.add(iArr2, iArr3, iArr4);
        C1380F.carry(iArr4);
        C1380F.sqr(pointProjective.f1122z, iArr5);
        C1380F.add(iArr5, iArr5, iArr5);
        C1380F.carry(iArr5);
        C1380F.sub(iArr4, iArr5, iArr6);
        C1380F.sub(iArr, iArr4, iArr);
        C1380F.sub(iArr2, iArr3, iArr2);
        C1380F.mul(iArr, iArr6, pointProjective.f1120x);
        C1380F.mul(iArr4, iArr2, pointProjective.f1121y);
        C1380F.mul(iArr4, iArr6, pointProjective.f1122z);
    }

    private static void pointLookup(int i, int i2, PointAffine pointAffine) {
        int i3 = i * 512;
        for (int i4 = 0; i4 < 16; i4++) {
            int i5 = ((i4 ^ i2) - 1) >> 31;
            C1380F.cmov(i5, PRECOMP_BASE_COMB, i3, pointAffine.f1118x, 0);
            C1380F.cmov(i5, PRECOMP_BASE_COMB, i3 + 16, pointAffine.f1119y, 0);
            i3 += 32;
        }
    }

    private static void pointLookup(int[] iArr, int i, int[] iArr2, PointProjective pointProjective) {
        int window4 = getWindow4(iArr, i);
        int i2 = (window4 >>> 3) ^ 1;
        int i3 = (window4 ^ (-i2)) & 7;
        int i4 = 0;
        for (int i5 = 0; i5 < 8; i5++) {
            int i6 = ((i5 ^ i3) - 1) >> 31;
            C1380F.cmov(i6, iArr2, i4, pointProjective.f1120x, 0);
            C1380F.cmov(i6, iArr2, i4 + 16, pointProjective.f1121y, 0);
            C1380F.cmov(i6, iArr2, i4 + 32, pointProjective.f1122z, 0);
            i4 += 48;
        }
        C1380F.cnegate(i2, pointProjective.f1120x);
    }

    private static void pointLookup15(int[] iArr, PointProjective pointProjective) {
        C1380F.copy(iArr, 336, pointProjective.f1120x, 0);
        C1380F.copy(iArr, 352, pointProjective.f1121y, 0);
        C1380F.copy(iArr, 368, pointProjective.f1122z, 0);
    }

    private static void pointPrecompute(PointAffine pointAffine, PointProjective[] pointProjectiveArr, int i, int i2, PointTemp pointTemp) {
        PointProjective pointProjective = new PointProjective();
        pointCopy(pointAffine, pointProjective);
        pointDouble(pointProjective, pointTemp);
        PointProjective pointProjective2 = new PointProjective();
        pointProjectiveArr[i] = pointProjective2;
        pointCopy(pointAffine, pointProjective2);
        for (int i3 = 1; i3 < i2; i3++) {
            int i4 = i + i3;
            PointProjective pointProjective3 = new PointProjective();
            pointProjectiveArr[i4] = pointProjective3;
            pointCopy(pointProjectiveArr[i4 - 1], pointProjective3);
            pointAdd(pointProjective, pointProjectiveArr[i4], pointTemp);
        }
    }

    private static int[] pointPrecompute(PointProjective pointProjective, int i, PointTemp pointTemp) {
        PointProjective pointProjective2 = new PointProjective();
        pointCopy(pointProjective, pointProjective2);
        PointProjective pointProjective3 = new PointProjective();
        pointCopy(pointProjective, pointProjective3);
        pointDouble(pointProjective3, pointTemp);
        int[] createTable = C1380F.createTable(i * 3);
        int i2 = 0;
        int i3 = 0;
        while (true) {
            C1380F.copy(pointProjective2.f1120x, 0, createTable, i2);
            C1380F.copy(pointProjective2.f1121y, 0, createTable, i2 + 16);
            C1380F.copy(pointProjective2.f1122z, 0, createTable, i2 + 32);
            i2 += 48;
            i3++;
            if (i3 == i) {
                return createTable;
            }
            pointAdd(pointProjective3, pointProjective2, pointTemp);
        }
    }

    private static void pointSetNeutral(PointProjective pointProjective) {
        C1380F.zero(pointProjective.f1120x);
        C1380F.one(pointProjective.f1121y);
        C1380F.one(pointProjective.f1122z);
    }

    public static void precompute() {
        int i;
        synchronized (PRECOMP_LOCK) {
            if (PRECOMP_BASE_COMB != null) {
                return;
            }
            PointProjective[] pointProjectiveArr = new PointProjective[CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA];
            PointTemp pointTemp = new PointTemp();
            PointAffine pointAffine = new PointAffine();
            C1380F.copy(B_x, 0, pointAffine.f1118x, 0);
            C1380F.copy(B_y, 0, pointAffine.f1119y, 0);
            pointPrecompute(pointAffine, pointProjectiveArr, 0, 32, pointTemp);
            PointAffine pointAffine2 = new PointAffine();
            C1380F.copy(B225_x, 0, pointAffine2.f1118x, 0);
            C1380F.copy(B225_y, 0, pointAffine2.f1119y, 0);
            pointPrecompute(pointAffine2, pointProjectiveArr, 32, 32, pointTemp);
            PointProjective pointProjective = new PointProjective();
            pointCopy(pointAffine, pointProjective);
            int i2 = 5;
            PointProjective[] pointProjectiveArr2 = new PointProjective[5];
            for (int i3 = 0; i3 < 5; i3++) {
                pointProjectiveArr2[i3] = new PointProjective();
            }
            int i4 = 0;
            int i5 = 64;
            while (i4 < i2) {
                int i6 = i5 + 1;
                PointProjective pointProjective2 = new PointProjective();
                pointProjectiveArr[i5] = pointProjective2;
                int i7 = 0;
                while (true) {
                    i = 1;
                    if (i7 >= i2) {
                        break;
                    }
                    if (i7 == 0) {
                        pointCopy(pointProjective, pointProjective2);
                    } else {
                        pointAdd(pointProjective, pointProjective2, pointTemp);
                    }
                    pointDouble(pointProjective, pointTemp);
                    pointCopy(pointProjective, pointProjectiveArr2[i7]);
                    if (i4 + i7 != 8) {
                        while (i < 18) {
                            pointDouble(pointProjective, pointTemp);
                            i++;
                        }
                    }
                    i7++;
                    i2 = 5;
                }
                C1380F.negate(pointProjective2.f1120x, pointProjective2.f1120x);
                int i8 = 0;
                i5 = i6;
                while (i8 < 4) {
                    int i9 = i << i8;
                    int i10 = 0;
                    while (i10 < i9) {
                        PointProjective pointProjective3 = new PointProjective();
                        pointProjectiveArr[i5] = pointProjective3;
                        pointCopy(pointProjectiveArr[i5 - i9], pointProjective3);
                        pointAdd(pointProjectiveArr2[i8], pointProjectiveArr[i5], pointTemp);
                        i10++;
                        i5++;
                    }
                    i8++;
                    i = 1;
                }
                i4++;
                i2 = 5;
            }
            invertZs(pointProjectiveArr);
            PRECOMP_BASE_WNAF = new PointAffine[32];
            for (int i11 = 0; i11 < 32; i11++) {
                PointProjective pointProjective4 = pointProjectiveArr[i11];
                PointAffine[] pointAffineArr = PRECOMP_BASE_WNAF;
                PointAffine pointAffine3 = new PointAffine();
                pointAffineArr[i11] = pointAffine3;
                C1380F.mul(pointProjective4.f1120x, pointProjective4.f1122z, pointAffine3.f1118x);
                C1380F.normalize(pointAffine3.f1118x);
                C1380F.mul(pointProjective4.f1121y, pointProjective4.f1122z, pointAffine3.f1119y);
                C1380F.normalize(pointAffine3.f1119y);
            }
            PRECOMP_BASE225_WNAF = new PointAffine[32];
            for (int i12 = 0; i12 < 32; i12++) {
                PointProjective pointProjective5 = pointProjectiveArr[32 + i12];
                PointAffine[] pointAffineArr2 = PRECOMP_BASE225_WNAF;
                PointAffine pointAffine4 = new PointAffine();
                pointAffineArr2[i12] = pointAffine4;
                C1380F.mul(pointProjective5.f1120x, pointProjective5.f1122z, pointAffine4.f1118x);
                C1380F.normalize(pointAffine4.f1118x);
                C1380F.mul(pointProjective5.f1121y, pointProjective5.f1122z, pointAffine4.f1119y);
                C1380F.normalize(pointAffine4.f1119y);
            }
            PRECOMP_BASE_COMB = C1380F.createTable(CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256);
            int i13 = 0;
            for (int i14 = 64; i14 < 144; i14++) {
                PointProjective pointProjective6 = pointProjectiveArr[i14];
                C1380F.mul(pointProjective6.f1120x, pointProjective6.f1122z, pointProjective6.f1120x);
                C1380F.normalize(pointProjective6.f1120x);
                C1380F.mul(pointProjective6.f1121y, pointProjective6.f1122z, pointProjective6.f1121y);
                C1380F.normalize(pointProjective6.f1121y);
                C1380F.copy(pointProjective6.f1120x, 0, PRECOMP_BASE_COMB, i13);
                C1380F.copy(pointProjective6.f1121y, 0, PRECOMP_BASE_COMB, i13 + 16);
                i13 += 32;
            }
        }
    }

    private static void pruneScalar(byte[] bArr, int i, byte[] bArr2) {
        System.arraycopy(bArr, i, bArr2, 0, 56);
        bArr2[0] = (byte) (bArr2[0] & 252);
        bArr2[55] = (byte) (bArr2[55] | ByteCompanionObject.MIN_VALUE);
        bArr2[56] = 0;
    }

    private static void scalarMult(byte[] bArr, PointProjective pointProjective, PointProjective pointProjective2) {
        int[] iArr = new int[15];
        Scalar448.decode(bArr, iArr);
        Scalar448.toSignedDigits(449, iArr, iArr);
        PointProjective pointProjective3 = new PointProjective();
        PointTemp pointTemp = new PointTemp();
        int[] pointPrecompute = pointPrecompute(pointProjective, 8, pointTemp);
        pointLookup15(pointPrecompute, pointProjective2);
        pointAdd(pointProjective, pointProjective2, pointTemp);
        int i = 111;
        while (true) {
            pointLookup(iArr, i, pointPrecompute, pointProjective3);
            pointAdd(pointProjective3, pointProjective2, pointTemp);
            i--;
            if (i < 0) {
                return;
            }
            for (int i2 = 0; i2 < 4; i2++) {
                pointDouble(pointProjective2, pointTemp);
            }
        }
    }

    private static void scalarMultBase(byte[] bArr, PointProjective pointProjective) {
        precompute();
        int[] iArr = new int[15];
        Scalar448.decode(bArr, iArr);
        Scalar448.toSignedDigits(PRECOMP_RANGE, iArr, iArr);
        PointAffine pointAffine = new PointAffine();
        PointTemp pointTemp = new PointTemp();
        pointSetNeutral(pointProjective);
        int i = 17;
        while (true) {
            int i2 = i;
            for (int i3 = 0; i3 < 5; i3++) {
                int i4 = 0;
                for (int i5 = 0; i5 < 5; i5++) {
                    i4 = (i4 & (~(1 << i5))) ^ ((iArr[i2 >>> 5] >>> (i2 & 31)) << i5);
                    i2 += 18;
                }
                int i6 = (i4 >>> 4) & 1;
                pointLookup(i3, ((-i6) ^ i4) & 15, pointAffine);
                C1380F.cnegate(i6, pointAffine.f1118x);
                pointAdd(pointAffine, pointProjective, pointTemp);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointProjective, pointTemp);
        }
    }

    private static void scalarMultBaseEncoded(byte[] bArr, byte[] bArr2, int i) {
        PointProjective pointProjective = new PointProjective();
        scalarMultBase(bArr, pointProjective);
        if (encodeResult(pointProjective, bArr2, i) == 0) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseXY(X448.Friend friend, byte[] bArr, int i, int[] iArr, int[] iArr2) {
        if (friend == null) {
            throw new NullPointerException("This method is only for use by X448");
        }
        byte[] bArr2 = new byte[57];
        pruneScalar(bArr, i, bArr2);
        PointProjective pointProjective = new PointProjective();
        scalarMultBase(bArr2, pointProjective);
        if (checkPoint(pointProjective) == 0) {
            throw new IllegalStateException();
        }
        C1380F.copy(pointProjective.f1120x, 0, iArr, 0);
        C1380F.copy(pointProjective.f1121y, 0, iArr2, 0);
    }

    private static void scalarMultOrderVar(PointAffine pointAffine, PointProjective pointProjective) {
        byte[] bArr = new byte[447];
        Scalar448.getOrderWnafVar(5, bArr);
        PointProjective[] pointProjectiveArr = new PointProjective[8];
        PointTemp pointTemp = new PointTemp();
        pointPrecompute(pointAffine, pointProjectiveArr, 0, 8, pointTemp);
        pointSetNeutral(pointProjective);
        int i = 446;
        while (true) {
            byte b = bArr[i];
            if (b != 0) {
                pointAddVar(b < 0, pointProjectiveArr[(b >> 1) ^ (b >> 31)], pointProjective, pointTemp);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointProjective, pointTemp);
        }
    }

    private static void scalarMultStraus225Var(int[] iArr, int[] iArr2, PointAffine pointAffine, int[] iArr3, PointAffine pointAffine2, PointProjective pointProjective) {
        int i;
        precompute();
        byte[] bArr = new byte[PRECOMP_RANGE];
        int i2 = 225;
        byte[] bArr2 = new byte[225];
        byte[] bArr3 = new byte[225];
        Wnaf.getSignedVar(iArr, 7, bArr);
        Wnaf.getSignedVar(iArr2, 5, bArr2);
        Wnaf.getSignedVar(iArr3, 5, bArr3);
        PointProjective[] pointProjectiveArr = new PointProjective[8];
        PointProjective[] pointProjectiveArr2 = new PointProjective[8];
        PointTemp pointTemp = new PointTemp();
        pointPrecompute(pointAffine, pointProjectiveArr, 0, 8, pointTemp);
        pointPrecompute(pointAffine2, pointProjectiveArr2, 0, 8, pointTemp);
        pointSetNeutral(pointProjective);
        while (true) {
            i = i2 - 1;
            if (i < 0 || (bArr[i] | bArr[i2 + BERTags.FLAGS] | bArr2[i] | bArr3[i]) != 0) {
                break;
            }
            i2 = i;
        }
        while (i >= 0) {
            byte b = bArr[i];
            if (b != 0) {
                pointAddVar(b < 0, PRECOMP_BASE_WNAF[(b >> 1) ^ (b >> 31)], pointProjective, pointTemp);
            }
            byte b2 = bArr[i + 225];
            if (b2 != 0) {
                pointAddVar(b2 < 0, PRECOMP_BASE225_WNAF[(b2 >> 1) ^ (b2 >> 31)], pointProjective, pointTemp);
            }
            byte b3 = bArr2[i];
            if (b3 != 0) {
                pointAddVar(b3 < 0, pointProjectiveArr[(b3 >> 1) ^ (b3 >> 31)], pointProjective, pointTemp);
            }
            byte b4 = bArr3[i];
            if (b4 != 0) {
                pointAddVar(b4 < 0, pointProjectiveArr2[(b4 >> 1) ^ (b4 >> 31)], pointProjective, pointTemp);
            }
            pointDouble(pointProjective, pointTemp);
            i--;
        }
        pointDouble(pointProjective, pointTemp);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4, byte[] bArr5, int i5) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4, bArr5, i5);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        implSign(bArr, i, bArr2, (byte) 0, bArr3, i2, i3, bArr4, i4);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Xof xof, byte[] bArr4, int i3) {
        byte[] bArr5 = new byte[64];
        if (64 != xof.doFinal(bArr5, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr5, 0, 64, bArr4, i3);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, byte[] bArr5, int i4) {
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64, bArr5, i4);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, Xof xof, byte[] bArr3, int i2) {
        byte[] bArr4 = new byte[64];
        if (64 != xof.doFinal(bArr4, 0, 64)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, (byte) 1, bArr4, 0, 64, bArr3, i2);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, byte[] bArr3, int i2, byte[] bArr4, int i3) {
        implSign(bArr, i, bArr2, (byte) 1, bArr3, i2, 64, bArr4, i3);
    }

    public static boolean validatePublicKeyFull(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 57);
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
        byte[] copy = copy(bArr, i, 57);
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
        byte[] copy = copy(bArr, i, 57);
        if (checkPointFullVar(copy)) {
            return decodePointVar(copy, false, new PointAffine());
        }
        return false;
    }

    public static PublicPoint validatePublicKeyPartialExport(byte[] bArr, int i) {
        byte[] copy = copy(bArr, i, 57);
        if (checkPointFullVar(copy)) {
            PointAffine pointAffine = new PointAffine();
            if (decodePointVar(copy, false, pointAffine)) {
                return exportPoint(pointAffine);
            }
            return null;
        }
        return null;
    }

    public static boolean verify(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte[] bArr3, int i2, int i3) {
        return implVerify(bArr, i, publicPoint, bArr2, (byte) 0, bArr3, i2, i3);
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, Xof xof) {
        byte[] bArr3 = new byte[64];
        if (64 == xof.doFinal(bArr3, 0, 64)) {
            return implVerify(bArr, i, publicPoint, bArr2, (byte) 1, bArr3, 0, 64);
        }
        throw new IllegalArgumentException("ph");
    }

    public static boolean verifyPrehash(byte[] bArr, int i, PublicPoint publicPoint, byte[] bArr2, byte[] bArr3, int i2) {
        return implVerify(bArr, i, publicPoint, bArr2, (byte) 1, bArr3, i2, 64);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Xof xof) {
        byte[] bArr4 = new byte[64];
        if (64 == xof.doFinal(bArr4, 0, 64)) {
            return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, 0, 64);
        }
        throw new IllegalArgumentException("ph");
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64);
    }
}