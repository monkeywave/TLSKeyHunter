package org.bouncycastle.math.p010ec.rfc8032;

import java.security.SecureRandom;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.math.p010ec.rfc7748.X25519;
import org.bouncycastle.math.p010ec.rfc7748.X25519Field;
import org.bouncycastle.math.raw.Interleave;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519 */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519.class */
public abstract class Ed25519 {
    private static final long M08L = 255;
    private static final long M28L = 268435455;
    private static final long M32L = 4294967295L;
    private static final int COORD_INTS = 8;
    private static final int POINT_BYTES = 32;
    private static final int SCALAR_INTS = 8;
    private static final int SCALAR_BYTES = 32;
    public static final int PREHASH_SIZE = 64;
    public static final int PUBLIC_KEY_SIZE = 32;
    public static final int SECRET_KEY_SIZE = 32;
    public static final int SIGNATURE_SIZE = 64;

    /* renamed from: L0 */
    private static final int f765L0 = -50998291;

    /* renamed from: L1 */
    private static final int f766L1 = 19280294;

    /* renamed from: L2 */
    private static final int f767L2 = 127719000;

    /* renamed from: L3 */
    private static final int f768L3 = -6428113;

    /* renamed from: L4 */
    private static final int f769L4 = 5343;
    private static final int WNAF_WIDTH_BASE = 7;
    private static final int PRECOMP_BLOCKS = 8;
    private static final int PRECOMP_TEETH = 4;
    private static final int PRECOMP_SPACING = 8;
    private static final int PRECOMP_POINTS = 8;
    private static final int PRECOMP_MASK = 7;
    private static final byte[] DOM2_PREFIX = {83, 105, 103, 69, 100, 50, 53, 53, 49, 57, 32, 110, 111, 32, 69, 100, 50, 53, 53, 49, 57, 32, 99, 111, 108, 108, 105, 115, 105, 111, 110, 115};

    /* renamed from: P */
    private static final int[] f763P = {-19, -1, -1, -1, -1, -1, -1, Integer.MAX_VALUE};

    /* renamed from: L */
    private static final int[] f764L = {1559614445, 1477600026, -1560830762, 350157278, 0, 0, 0, 268435456};
    private static final int[] B_x = {52811034, 25909283, 8072341, 50637101, 13785486, 30858332, 20483199, 20966410, 43936626, 4379245};
    private static final int[] B_y = {40265304, 26843545, 6710886, 53687091, 13421772, 40265318, 26843545, 6710886, 53687091, 13421772};
    private static final int[] C_d = {56195235, 47411844, 25868126, 40503822, 57364, 58321048, 30416477, 31930572, 57760639, 10749657};
    private static final int[] C_d2 = {45281625, 27714825, 18181821, 13898781, 114729, 49533232, 60832955, 30306712, 48412415, 4722099};
    private static final int[] C_d4 = {23454386, 55429651, 2809210, 27797563, 229458, 31957600, 54557047, 27058993, 29715967, 9444199};
    private static final Object precompLock = new Object();
    private static PointExt[] precompBaseTable = null;
    private static int[] precompBase = null;

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$Algorithm */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$Algorithm.class */
    public static final class Algorithm {
        public static final int Ed25519 = 0;
        public static final int Ed25519ctx = 1;
        public static final int Ed25519ph = 2;
    }

    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$F */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$F.class */
    private static class C0322F extends X25519Field {
        private C0322F() {
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointAccum */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$PointAccum.class */
    public static class PointAccum {

        /* renamed from: x */
        int[] f770x;

        /* renamed from: y */
        int[] f771y;

        /* renamed from: z */
        int[] f772z;

        /* renamed from: u */
        int[] f773u;

        /* renamed from: v */
        int[] f774v;

        private PointAccum() {
            this.f770x = C0322F.create();
            this.f771y = C0322F.create();
            this.f772z = C0322F.create();
            this.f773u = C0322F.create();
            this.f774v = C0322F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointAffine */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$PointAffine.class */
    public static class PointAffine {

        /* renamed from: x */
        int[] f775x;

        /* renamed from: y */
        int[] f776y;

        private PointAffine() {
            this.f775x = C0322F.create();
            this.f776y = C0322F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointExt */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$PointExt.class */
    public static class PointExt {

        /* renamed from: x */
        int[] f777x;

        /* renamed from: y */
        int[] f778y;

        /* renamed from: z */
        int[] f779z;

        /* renamed from: t */
        int[] f780t;

        private PointExt() {
            this.f777x = C0322F.create();
            this.f778y = C0322F.create();
            this.f779z = C0322F.create();
            this.f780t = C0322F.create();
        }
    }

    /* JADX INFO: Access modifiers changed from: private */
    /* renamed from: org.bouncycastle.math.ec.rfc8032.Ed25519$PointPrecomp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc8032/Ed25519$PointPrecomp.class */
    public static class PointPrecomp {
        int[] ypx_h;
        int[] ymx_h;
        int[] xyd;

        private PointPrecomp() {
            this.ypx_h = C0322F.create();
            this.ymx_h = C0322F.create();
            this.xyd = C0322F.create();
        }
    }

    private static byte[] calculateS(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int[] iArr = new int[16];
        decodeScalar(bArr, 0, iArr);
        int[] iArr2 = new int[8];
        decodeScalar(bArr2, 0, iArr2);
        int[] iArr3 = new int[8];
        decodeScalar(bArr3, 0, iArr3);
        Nat256.mulAddTo(iArr2, iArr3, iArr);
        byte[] bArr4 = new byte[64];
        for (int i = 0; i < iArr.length; i++) {
            encode32(iArr[i], bArr4, i * 4);
        }
        return reduceScalar(bArr4);
    }

    private static boolean checkContextVar(byte[] bArr, byte b) {
        return (bArr == null && b == 0) || (bArr != null && bArr.length < 256);
    }

    private static int checkPoint(int[] iArr, int[] iArr2) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        C0322F.sqr(iArr, create2);
        C0322F.sqr(iArr2, create3);
        C0322F.mul(create2, create3, create);
        C0322F.sub(create3, create2, create3);
        C0322F.mul(create, C_d, create);
        C0322F.addOne(create);
        C0322F.sub(create, create3, create);
        C0322F.normalize(create);
        return C0322F.isZero(create);
    }

    private static int checkPoint(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] create4 = C0322F.create();
        C0322F.sqr(iArr, create2);
        C0322F.sqr(iArr2, create3);
        C0322F.sqr(iArr3, create4);
        C0322F.mul(create2, create3, create);
        C0322F.sub(create3, create2, create3);
        C0322F.mul(create3, create4, create3);
        C0322F.sqr(create4, create4);
        C0322F.mul(create, C_d, create);
        C0322F.add(create, create4, create);
        C0322F.sub(create, create3, create);
        C0322F.normalize(create);
        return C0322F.isZero(create);
    }

    private static boolean checkPointVar(byte[] bArr) {
        int[] iArr = new int[8];
        decode32(bArr, 0, iArr, 0, 8);
        iArr[7] = iArr[7] & Integer.MAX_VALUE;
        return !Nat256.gte(iArr, f763P);
    }

    private static boolean checkScalarVar(byte[] bArr, int[] iArr) {
        decodeScalar(bArr, 0, iArr);
        return !Nat256.gte(iArr, f764L);
    }

    private static byte[] copy(byte[] bArr, int i, int i2) {
        byte[] bArr2 = new byte[i2];
        System.arraycopy(bArr, i, bArr2, 0, i2);
        return bArr2;
    }

    private static Digest createDigest() {
        return new SHA512Digest();
    }

    public static Digest createPrehash() {
        return createDigest();
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

    private static boolean decodePointVar(byte[] bArr, int i, boolean z, PointAffine pointAffine) {
        byte[] copy = copy(bArr, i, 32);
        if (checkPointVar(copy)) {
            int i2 = (copy[31] & 128) >>> 7;
            copy[31] = (byte) (copy[31] & Byte.MAX_VALUE);
            C0322F.decode(copy, 0, pointAffine.f776y);
            int[] create = C0322F.create();
            int[] create2 = C0322F.create();
            C0322F.sqr(pointAffine.f776y, create);
            C0322F.mul(C_d, create, create2);
            C0322F.subOne(create);
            C0322F.addOne(create2);
            if (C0322F.sqrtRatioVar(create, create2, pointAffine.f775x)) {
                C0322F.normalize(pointAffine.f775x);
                if (i2 == 1 && C0322F.isZeroVar(pointAffine.f775x)) {
                    return false;
                }
                if (z ^ (i2 != (pointAffine.f775x[0] & 1))) {
                    C0322F.negate(pointAffine.f775x, pointAffine.f775x);
                    return true;
                }
                return true;
            }
            return false;
        }
        return false;
    }

    private static void decodeScalar(byte[] bArr, int i, int[] iArr) {
        decode32(bArr, i, iArr, 0, 8);
    }

    private static void dom2(Digest digest, byte b, byte[] bArr) {
        if (bArr != null) {
            int length = DOM2_PREFIX.length;
            byte[] bArr2 = new byte[length + 2 + bArr.length];
            System.arraycopy(DOM2_PREFIX, 0, bArr2, 0, length);
            bArr2[length] = b;
            bArr2[length + 1] = (byte) bArr.length;
            System.arraycopy(bArr, 0, bArr2, length + 2, bArr.length);
            digest.update(bArr2, 0, bArr2.length);
        }
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

    private static int encodePoint(PointAccum pointAccum, byte[] bArr, int i) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        C0322F.inv(pointAccum.f772z, create2);
        C0322F.mul(pointAccum.f770x, create2, create);
        C0322F.mul(pointAccum.f771y, create2, create2);
        C0322F.normalize(create);
        C0322F.normalize(create2);
        int checkPoint = checkPoint(create, create2);
        C0322F.encode(create2, bArr, i);
        int i2 = (i + 32) - 1;
        bArr[i2] = (byte) (bArr[i2] | ((create[0] & 1) << 7));
        return checkPoint;
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        secureRandom.nextBytes(bArr);
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        Digest createDigest = createDigest();
        byte[] bArr3 = new byte[createDigest.getDigestSize()];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr3, 0);
        byte[] bArr4 = new byte[32];
        pruneScalar(bArr3, 0, bArr4);
        scalarMultBaseEncoded(bArr4, bArr2, i2);
    }

    private static int getWindow4(int[] iArr, int i) {
        return (iArr[i >>> 3] >>> ((i & 7) << 2)) & 15;
    }

    private static byte[] getWnafVar(int[] iArr, int i) {
        int[] iArr2 = new int[16];
        int length = iArr2.length;
        int i2 = 0;
        int i3 = 8;
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
        byte[] bArr = new byte[253];
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

    private static void implSign(Digest digest, byte[] bArr, byte[] bArr2, byte[] bArr3, int i, byte[] bArr4, byte b, byte[] bArr5, int i2, int i3, byte[] bArr6, int i4) {
        dom2(digest, b, bArr4);
        digest.update(bArr, 32, 32);
        digest.update(bArr5, i2, i3);
        digest.doFinal(bArr, 0);
        byte[] reduceScalar = reduceScalar(bArr);
        byte[] bArr7 = new byte[32];
        scalarMultBaseEncoded(reduceScalar, bArr7, 0);
        dom2(digest, b, bArr4);
        digest.update(bArr7, 0, 32);
        digest.update(bArr3, i, 32);
        digest.update(bArr5, i2, i3);
        digest.doFinal(bArr, 0);
        byte[] calculateS = calculateS(reduceScalar, reduceScalar(bArr), bArr2);
        System.arraycopy(bArr7, 0, bArr6, i4, 32);
        System.arraycopy(calculateS, 0, bArr6, i4 + 32, 32);
    }

    private static void implSign(byte[] bArr, int i, byte[] bArr2, byte b, byte[] bArr3, int i2, int i3, byte[] bArr4, int i4) {
        if (!checkContextVar(bArr2, b)) {
            throw new IllegalArgumentException("ctx");
        }
        Digest createDigest = createDigest();
        byte[] bArr5 = new byte[createDigest.getDigestSize()];
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
        byte[] bArr6 = new byte[createDigest.getDigestSize()];
        createDigest.update(bArr, i, 32);
        createDigest.doFinal(bArr6, 0);
        byte[] bArr7 = new byte[32];
        pruneScalar(bArr6, 0, bArr7);
        implSign(createDigest, bArr6, bArr7, bArr2, i2, bArr3, b, bArr4, i3, i4, bArr5, i5);
    }

    private static boolean implVerify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte b, byte[] bArr4, int i3, int i4) {
        if (checkContextVar(bArr3, b)) {
            byte[] copy = copy(bArr, i, 32);
            byte[] copy2 = copy(bArr, i + 32, 32);
            if (checkPointVar(copy)) {
                int[] iArr = new int[8];
                if (checkScalarVar(copy2, iArr)) {
                    PointAffine pointAffine = new PointAffine();
                    if (decodePointVar(bArr2, i2, true, pointAffine)) {
                        Digest createDigest = createDigest();
                        byte[] bArr5 = new byte[createDigest.getDigestSize()];
                        dom2(createDigest, b, bArr3);
                        createDigest.update(copy, 0, 32);
                        createDigest.update(bArr2, i2, 32);
                        createDigest.update(bArr4, i3, i4);
                        createDigest.doFinal(bArr5, 0);
                        byte[] reduceScalar = reduceScalar(bArr5);
                        int[] iArr2 = new int[8];
                        decodeScalar(reduceScalar, 0, iArr2);
                        PointAccum pointAccum = new PointAccum();
                        scalarMultStrausVar(iArr, iArr2, pointAffine, pointAccum);
                        byte[] bArr6 = new byte[32];
                        return 0 != encodePoint(pointAccum, bArr6, 0) && Arrays.areEqual(bArr6, copy);
                    }
                    return false;
                }
                return false;
            }
            return false;
        }
        throw new IllegalArgumentException("ctx");
    }

    private static boolean isNeutralElementVar(int[] iArr, int[] iArr2) {
        return C0322F.isZeroVar(iArr) && C0322F.isOneVar(iArr2);
    }

    private static boolean isNeutralElementVar(int[] iArr, int[] iArr2, int[] iArr3) {
        return C0322F.isZeroVar(iArr) && C0322F.areEqualVar(iArr2, iArr3);
    }

    private static void pointAdd(PointExt pointExt, PointAccum pointAccum) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] create4 = C0322F.create();
        int[] iArr = pointAccum.f773u;
        int[] create5 = C0322F.create();
        int[] create6 = C0322F.create();
        int[] iArr2 = pointAccum.f774v;
        C0322F.apm(pointAccum.f771y, pointAccum.f770x, create2, create);
        C0322F.apm(pointExt.f778y, pointExt.f777x, create4, create3);
        C0322F.mul(create, create3, create);
        C0322F.mul(create2, create4, create2);
        C0322F.mul(pointAccum.f773u, pointAccum.f774v, create3);
        C0322F.mul(create3, pointExt.f780t, create3);
        C0322F.mul(create3, C_d2, create3);
        C0322F.mul(pointAccum.f772z, pointExt.f779z, create4);
        C0322F.add(create4, create4, create4);
        C0322F.apm(create2, create, iArr2, iArr);
        C0322F.apm(create4, create3, create6, create5);
        C0322F.carry(create6);
        C0322F.mul(iArr, create5, pointAccum.f770x);
        C0322F.mul(create6, iArr2, pointAccum.f771y);
        C0322F.mul(create5, create6, pointAccum.f772z);
    }

    private static void pointAdd(PointExt pointExt, PointExt pointExt2) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] create4 = C0322F.create();
        int[] create5 = C0322F.create();
        int[] create6 = C0322F.create();
        int[] create7 = C0322F.create();
        int[] create8 = C0322F.create();
        C0322F.apm(pointExt.f778y, pointExt.f777x, create2, create);
        C0322F.apm(pointExt2.f778y, pointExt2.f777x, create4, create3);
        C0322F.mul(create, create3, create);
        C0322F.mul(create2, create4, create2);
        C0322F.mul(pointExt.f780t, pointExt2.f780t, create3);
        C0322F.mul(create3, C_d2, create3);
        C0322F.mul(pointExt.f779z, pointExt2.f779z, create4);
        C0322F.add(create4, create4, create4);
        C0322F.apm(create2, create, create8, create5);
        C0322F.apm(create4, create3, create7, create6);
        C0322F.carry(create7);
        C0322F.mul(create5, create6, pointExt2.f777x);
        C0322F.mul(create7, create8, pointExt2.f778y);
        C0322F.mul(create6, create7, pointExt2.f779z);
        C0322F.mul(create5, create8, pointExt2.f780t);
    }

    private static void pointAddVar(boolean z, PointExt pointExt, PointAccum pointAccum) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] create4 = C0322F.create();
        int[] iArr5 = pointAccum.f773u;
        int[] create5 = C0322F.create();
        int[] create6 = C0322F.create();
        int[] iArr6 = pointAccum.f774v;
        if (z) {
            iArr = create4;
            iArr2 = create3;
            iArr3 = create6;
            iArr4 = create5;
        } else {
            iArr = create3;
            iArr2 = create4;
            iArr3 = create5;
            iArr4 = create6;
        }
        C0322F.apm(pointAccum.f771y, pointAccum.f770x, create2, create);
        C0322F.apm(pointExt.f778y, pointExt.f777x, iArr2, iArr);
        C0322F.mul(create, create3, create);
        C0322F.mul(create2, create4, create2);
        C0322F.mul(pointAccum.f773u, pointAccum.f774v, create3);
        C0322F.mul(create3, pointExt.f780t, create3);
        C0322F.mul(create3, C_d2, create3);
        C0322F.mul(pointAccum.f772z, pointExt.f779z, create4);
        C0322F.add(create4, create4, create4);
        C0322F.apm(create2, create, iArr6, iArr5);
        C0322F.apm(create4, create3, iArr4, iArr3);
        C0322F.carry(iArr4);
        C0322F.mul(iArr5, create5, pointAccum.f770x);
        C0322F.mul(create6, iArr6, pointAccum.f771y);
        C0322F.mul(create5, create6, pointAccum.f772z);
    }

    private static void pointAddVar(boolean z, PointExt pointExt, PointExt pointExt2, PointExt pointExt3) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] create4 = C0322F.create();
        int[] create5 = C0322F.create();
        int[] create6 = C0322F.create();
        int[] create7 = C0322F.create();
        int[] create8 = C0322F.create();
        if (z) {
            iArr = create4;
            iArr2 = create3;
            iArr3 = create7;
            iArr4 = create6;
        } else {
            iArr = create3;
            iArr2 = create4;
            iArr3 = create6;
            iArr4 = create7;
        }
        C0322F.apm(pointExt.f778y, pointExt.f777x, create2, create);
        C0322F.apm(pointExt2.f778y, pointExt2.f777x, iArr2, iArr);
        C0322F.mul(create, create3, create);
        C0322F.mul(create2, create4, create2);
        C0322F.mul(pointExt.f780t, pointExt2.f780t, create3);
        C0322F.mul(create3, C_d2, create3);
        C0322F.mul(pointExt.f779z, pointExt2.f779z, create4);
        C0322F.add(create4, create4, create4);
        C0322F.apm(create2, create, create8, create5);
        C0322F.apm(create4, create3, iArr4, iArr3);
        C0322F.carry(iArr4);
        C0322F.mul(create5, create6, pointExt3.f777x);
        C0322F.mul(create7, create8, pointExt3.f778y);
        C0322F.mul(create6, create7, pointExt3.f779z);
        C0322F.mul(create5, create8, pointExt3.f780t);
    }

    private static void pointAddPrecomp(PointPrecomp pointPrecomp, PointAccum pointAccum) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] iArr = pointAccum.f773u;
        int[] create4 = C0322F.create();
        int[] create5 = C0322F.create();
        int[] iArr2 = pointAccum.f774v;
        C0322F.apm(pointAccum.f771y, pointAccum.f770x, create2, create);
        C0322F.mul(create, pointPrecomp.ymx_h, create);
        C0322F.mul(create2, pointPrecomp.ypx_h, create2);
        C0322F.mul(pointAccum.f773u, pointAccum.f774v, create3);
        C0322F.mul(create3, pointPrecomp.xyd, create3);
        C0322F.apm(create2, create, iArr2, iArr);
        C0322F.apm(pointAccum.f772z, create3, create5, create4);
        C0322F.carry(create5);
        C0322F.mul(iArr, create4, pointAccum.f770x);
        C0322F.mul(create5, iArr2, pointAccum.f771y);
        C0322F.mul(create4, create5, pointAccum.f772z);
    }

    private static PointExt pointCopy(PointAccum pointAccum) {
        PointExt pointExt = new PointExt();
        C0322F.copy(pointAccum.f770x, 0, pointExt.f777x, 0);
        C0322F.copy(pointAccum.f771y, 0, pointExt.f778y, 0);
        C0322F.copy(pointAccum.f772z, 0, pointExt.f779z, 0);
        C0322F.mul(pointAccum.f773u, pointAccum.f774v, pointExt.f780t);
        return pointExt;
    }

    private static PointExt pointCopy(PointAffine pointAffine) {
        PointExt pointExt = new PointExt();
        C0322F.copy(pointAffine.f775x, 0, pointExt.f777x, 0);
        C0322F.copy(pointAffine.f776y, 0, pointExt.f778y, 0);
        pointExtendXY(pointExt);
        return pointExt;
    }

    private static PointExt pointCopy(PointExt pointExt) {
        PointExt pointExt2 = new PointExt();
        pointCopy(pointExt, pointExt2);
        return pointExt2;
    }

    private static void pointCopy(PointAffine pointAffine, PointAccum pointAccum) {
        C0322F.copy(pointAffine.f775x, 0, pointAccum.f770x, 0);
        C0322F.copy(pointAffine.f776y, 0, pointAccum.f771y, 0);
        pointExtendXY(pointAccum);
    }

    private static void pointCopy(PointExt pointExt, PointExt pointExt2) {
        C0322F.copy(pointExt.f777x, 0, pointExt2.f777x, 0);
        C0322F.copy(pointExt.f778y, 0, pointExt2.f778y, 0);
        C0322F.copy(pointExt.f779z, 0, pointExt2.f779z, 0);
        C0322F.copy(pointExt.f780t, 0, pointExt2.f780t, 0);
    }

    private static void pointDouble(PointAccum pointAccum) {
        int[] create = C0322F.create();
        int[] create2 = C0322F.create();
        int[] create3 = C0322F.create();
        int[] iArr = pointAccum.f773u;
        int[] create4 = C0322F.create();
        int[] create5 = C0322F.create();
        int[] iArr2 = pointAccum.f774v;
        C0322F.sqr(pointAccum.f770x, create);
        C0322F.sqr(pointAccum.f771y, create2);
        C0322F.sqr(pointAccum.f772z, create3);
        C0322F.add(create3, create3, create3);
        C0322F.apm(create, create2, iArr2, create5);
        C0322F.add(pointAccum.f770x, pointAccum.f771y, iArr);
        C0322F.sqr(iArr, iArr);
        C0322F.sub(iArr2, iArr, iArr);
        C0322F.add(create3, create5, create4);
        C0322F.carry(create4);
        C0322F.mul(iArr, create4, pointAccum.f770x);
        C0322F.mul(create5, iArr2, pointAccum.f771y);
        C0322F.mul(create4, create5, pointAccum.f772z);
    }

    private static void pointExtendXY(PointAccum pointAccum) {
        C0322F.one(pointAccum.f772z);
        C0322F.copy(pointAccum.f770x, 0, pointAccum.f773u, 0);
        C0322F.copy(pointAccum.f771y, 0, pointAccum.f774v, 0);
    }

    private static void pointExtendXY(PointExt pointExt) {
        C0322F.one(pointExt.f779z);
        C0322F.mul(pointExt.f777x, pointExt.f778y, pointExt.f780t);
    }

    private static void pointLookup(int i, int i2, PointPrecomp pointPrecomp) {
        int i3 = i * 8 * 3 * 10;
        for (int i4 = 0; i4 < 8; i4++) {
            int i5 = ((i4 ^ i2) - 1) >> 31;
            C0322F.cmov(i5, precompBase, i3, pointPrecomp.ypx_h, 0);
            int i6 = i3 + 10;
            C0322F.cmov(i5, precompBase, i6, pointPrecomp.ymx_h, 0);
            int i7 = i6 + 10;
            C0322F.cmov(i5, precompBase, i7, pointPrecomp.xyd, 0);
            i3 = i7 + 10;
        }
    }

    private static void pointLookup(int[] iArr, int i, int[] iArr2, PointExt pointExt) {
        int window4 = getWindow4(iArr, i);
        int i2 = (window4 >>> 3) ^ 1;
        int i3 = (window4 ^ (-i2)) & 7;
        int i4 = 0;
        for (int i5 = 0; i5 < 8; i5++) {
            int i6 = ((i5 ^ i3) - 1) >> 31;
            C0322F.cmov(i6, iArr2, i4, pointExt.f777x, 0);
            int i7 = i4 + 10;
            C0322F.cmov(i6, iArr2, i7, pointExt.f778y, 0);
            int i8 = i7 + 10;
            C0322F.cmov(i6, iArr2, i8, pointExt.f779z, 0);
            int i9 = i8 + 10;
            C0322F.cmov(i6, iArr2, i9, pointExt.f780t, 0);
            i4 = i9 + 10;
        }
        C0322F.cnegate(i2, pointExt.f777x);
        C0322F.cnegate(i2, pointExt.f780t);
    }

    private static void pointLookup(int[] iArr, int i, PointExt pointExt) {
        int i2 = 40 * i;
        C0322F.copy(iArr, i2, pointExt.f777x, 0);
        int i3 = i2 + 10;
        C0322F.copy(iArr, i3, pointExt.f778y, 0);
        int i4 = i3 + 10;
        C0322F.copy(iArr, i4, pointExt.f779z, 0);
        C0322F.copy(iArr, i4 + 10, pointExt.f780t, 0);
    }

    private static int[] pointPrecompute(PointAffine pointAffine, int i) {
        PointExt pointCopy = pointCopy(pointAffine);
        PointExt pointCopy2 = pointCopy(pointCopy);
        pointAdd(pointCopy, pointCopy2);
        int[] createTable = C0322F.createTable(i * 4);
        int i2 = 0;
        int i3 = 0;
        while (true) {
            C0322F.copy(pointCopy.f777x, 0, createTable, i2);
            int i4 = i2 + 10;
            C0322F.copy(pointCopy.f778y, 0, createTable, i4);
            int i5 = i4 + 10;
            C0322F.copy(pointCopy.f779z, 0, createTable, i5);
            int i6 = i5 + 10;
            C0322F.copy(pointCopy.f780t, 0, createTable, i6);
            i2 = i6 + 10;
            i3++;
            if (i3 == i) {
                return createTable;
            }
            pointAdd(pointCopy2, pointCopy);
        }
    }

    private static PointExt[] pointPrecomputeVar(PointExt pointExt, int i) {
        PointExt pointExt2 = new PointExt();
        pointAddVar(false, pointExt, pointExt, pointExt2);
        PointExt[] pointExtArr = new PointExt[i];
        pointExtArr[0] = pointCopy(pointExt);
        for (int i2 = 1; i2 < i; i2++) {
            PointExt pointExt3 = pointExtArr[i2 - 1];
            PointExt pointExt4 = new PointExt();
            pointExtArr[i2] = pointExt4;
            pointAddVar(false, pointExt3, pointExt2, pointExt4);
        }
        return pointExtArr;
    }

    private static void pointSetNeutral(PointAccum pointAccum) {
        C0322F.zero(pointAccum.f770x);
        C0322F.one(pointAccum.f771y);
        C0322F.one(pointAccum.f772z);
        C0322F.zero(pointAccum.f773u);
        C0322F.one(pointAccum.f774v);
    }

    private static void pointSetNeutral(PointExt pointExt) {
        C0322F.zero(pointExt.f777x);
        C0322F.one(pointExt.f778y);
        C0322F.one(pointExt.f779z);
        C0322F.zero(pointExt.f780t);
    }

    public static void precompute() {
        synchronized (precompLock) {
            if (precompBase != null) {
                return;
            }
            PointExt pointExt = new PointExt();
            C0322F.copy(B_x, 0, pointExt.f777x, 0);
            C0322F.copy(B_y, 0, pointExt.f778y, 0);
            pointExtendXY(pointExt);
            precompBaseTable = pointPrecomputeVar(pointExt, 32);
            PointAccum pointAccum = new PointAccum();
            C0322F.copy(B_x, 0, pointAccum.f770x, 0);
            C0322F.copy(B_y, 0, pointAccum.f771y, 0);
            pointExtendXY(pointAccum);
            precompBase = C0322F.createTable(192);
            int i = 0;
            for (int i2 = 0; i2 < 8; i2++) {
                PointExt[] pointExtArr = new PointExt[4];
                PointExt pointExt2 = new PointExt();
                pointSetNeutral(pointExt2);
                for (int i3 = 0; i3 < 4; i3++) {
                    pointAddVar(true, pointExt2, pointCopy(pointAccum), pointExt2);
                    pointDouble(pointAccum);
                    pointExtArr[i3] = pointCopy(pointAccum);
                    if (i2 + i3 != 10) {
                        for (int i4 = 1; i4 < 8; i4++) {
                            pointDouble(pointAccum);
                        }
                    }
                }
                PointExt[] pointExtArr2 = new PointExt[8];
                int i5 = 0 + 1;
                pointExtArr2[0] = pointExt2;
                for (int i6 = 0; i6 < 3; i6++) {
                    int i7 = 1 << i6;
                    int i8 = 0;
                    while (i8 < i7) {
                        PointExt pointExt3 = pointExtArr2[i5 - i7];
                        PointExt pointExt4 = pointExtArr[i6];
                        PointExt pointExt5 = new PointExt();
                        pointExtArr2[i5] = pointExt5;
                        pointAddVar(false, pointExt3, pointExt4, pointExt5);
                        i8++;
                        i5++;
                    }
                }
                int[] createTable = C0322F.createTable(8);
                int[] create = C0322F.create();
                C0322F.copy(pointExtArr2[0].f779z, 0, create, 0);
                C0322F.copy(create, 0, createTable, 0);
                int i9 = 0;
                while (true) {
                    i9++;
                    if (i9 >= 8) {
                        break;
                    }
                    C0322F.mul(create, pointExtArr2[i9].f779z, create);
                    C0322F.copy(create, 0, createTable, i9 * 10);
                }
                C0322F.add(create, create, create);
                C0322F.invVar(create, create);
                int i10 = i9 - 1;
                int[] create2 = C0322F.create();
                while (i10 > 0) {
                    int i11 = i10;
                    i10--;
                    C0322F.copy(createTable, i10 * 10, create2, 0);
                    C0322F.mul(create2, create, create2);
                    C0322F.copy(create2, 0, createTable, i11 * 10);
                    C0322F.mul(create, pointExtArr2[i11].f779z, create);
                }
                C0322F.copy(create, 0, createTable, 0);
                for (int i12 = 0; i12 < 8; i12++) {
                    PointExt pointExt6 = pointExtArr2[i12];
                    int[] create3 = C0322F.create();
                    int[] create4 = C0322F.create();
                    C0322F.copy(createTable, i12 * 10, create4, 0);
                    C0322F.mul(pointExt6.f777x, create4, create3);
                    C0322F.mul(pointExt6.f778y, create4, create4);
                    PointPrecomp pointPrecomp = new PointPrecomp();
                    C0322F.apm(create4, create3, pointPrecomp.ypx_h, pointPrecomp.ymx_h);
                    C0322F.mul(create3, create4, pointPrecomp.xyd);
                    C0322F.mul(pointPrecomp.xyd, C_d4, pointPrecomp.xyd);
                    C0322F.normalize(pointPrecomp.ypx_h);
                    C0322F.normalize(pointPrecomp.ymx_h);
                    C0322F.copy(pointPrecomp.ypx_h, 0, precompBase, i);
                    int i13 = i + 10;
                    C0322F.copy(pointPrecomp.ymx_h, 0, precompBase, i13);
                    int i14 = i13 + 10;
                    C0322F.copy(pointPrecomp.xyd, 0, precompBase, i14);
                    i = i14 + 10;
                }
            }
        }
    }

    private static void pruneScalar(byte[] bArr, int i, byte[] bArr2) {
        System.arraycopy(bArr, i, bArr2, 0, 32);
        bArr2[0] = (byte) (bArr2[0] & 248);
        bArr2[31] = (byte) (bArr2[31] & Byte.MAX_VALUE);
        bArr2[31] = (byte) (bArr2[31] | 64);
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
        long j = bArr[63] & M08L;
        long j2 = decode245 - (j * (-50998291));
        long j3 = decode326 - (j * 19280294);
        long j4 = decode246 - (j * 127719000);
        long j5 = decode327 - (j * (-6428113));
        long j6 = decode247 - (j * 5343);
        long j7 = decode249 + (decode329 >> 28);
        long j8 = decode329 & M28L;
        long j9 = decode325 - (j7 * (-50998291));
        long j10 = j2 - (j7 * 19280294);
        long j11 = j3 - (j7 * 127719000);
        long j12 = j4 - (j7 * (-6428113));
        long j13 = j5 - (j7 * 5343);
        long j14 = decode244 - (j8 * (-50998291));
        long j15 = j9 - (j8 * 19280294);
        long j16 = j10 - (j8 * 127719000);
        long j17 = j11 - (j8 * (-6428113));
        long j18 = j12 - (j8 * 5343);
        long j19 = decode248 + (decode328 >> 28);
        long j20 = decode328 & M28L;
        long j21 = decode324 - (j19 * (-50998291));
        long j22 = j14 - (j19 * 19280294);
        long j23 = j15 - (j19 * 127719000);
        long j24 = j16 - (j19 * (-6428113));
        long j25 = j17 - (j19 * 5343);
        long j26 = decode243 - (j20 * (-50998291));
        long j27 = j21 - (j20 * 19280294);
        long j28 = j22 - (j20 * 127719000);
        long j29 = j23 - (j20 * (-6428113));
        long j30 = j24 - (j20 * 5343);
        long j31 = j6 + (j13 >> 28);
        long j32 = j13 & M28L;
        long j33 = decode323 - (j31 * (-50998291));
        long j34 = j26 - (j31 * 19280294);
        long j35 = j27 - (j31 * 127719000);
        long j36 = j28 - (j31 * (-6428113));
        long j37 = j29 - (j31 * 5343);
        long j38 = j32 + (j18 >> 28);
        long j39 = j18 & M28L;
        long j40 = decode242 - (j38 * (-50998291));
        long j41 = j33 - (j38 * 19280294);
        long j42 = j34 - (j38 * 127719000);
        long j43 = j35 - (j38 * (-6428113));
        long j44 = j36 - (j38 * 5343);
        long j45 = j39 + (j25 >> 28);
        long j46 = j25 & M28L;
        long j47 = decode322 - (j45 * (-50998291));
        long j48 = j40 - (j45 * 19280294);
        long j49 = j41 - (j45 * 127719000);
        long j50 = j42 - (j45 * (-6428113));
        long j51 = j43 - (j45 * 5343);
        long j52 = j46 + (j30 >> 28);
        long j53 = j30 & M28L;
        long j54 = decode24 - (j52 * (-50998291));
        long j55 = j47 - (j52 * 19280294);
        long j56 = j48 - (j52 * 127719000);
        long j57 = j49 - (j52 * (-6428113));
        long j58 = j50 - (j52 * 5343);
        long j59 = j37 + (j44 >> 28);
        long j60 = j44 & M28L;
        long j61 = j53 + (j59 >> 28);
        long j62 = j59 & M28L;
        long j63 = j62 >>> 27;
        long j64 = j61 + j63;
        long j65 = decode32 - (j64 * (-50998291));
        long j66 = j54 - (j64 * 19280294);
        long j67 = j55 - (j64 * 127719000);
        long j68 = j56 - (j64 * (-6428113));
        long j69 = j57 - (j64 * 5343);
        long j70 = j66 + (j65 >> 28);
        long j71 = j65 & M28L;
        long j72 = j67 + (j70 >> 28);
        long j73 = j70 & M28L;
        long j74 = j68 + (j72 >> 28);
        long j75 = j72 & M28L;
        long j76 = j69 + (j74 >> 28);
        long j77 = j74 & M28L;
        long j78 = j58 + (j76 >> 28);
        long j79 = j76 & M28L;
        long j80 = j51 + (j78 >> 28);
        long j81 = j78 & M28L;
        long j82 = j60 + (j80 >> 28);
        long j83 = j80 & M28L;
        long j84 = j62 + (j82 >> 28);
        long j85 = j82 & M28L;
        long j86 = j84 >> 28;
        long j87 = j84 & M28L;
        long j88 = j86 - j63;
        long j89 = j71 + (j88 & (-50998291));
        long j90 = j73 + (j88 & 19280294);
        long j91 = j75 + (j88 & 127719000);
        long j92 = j77 + (j88 & (-6428113));
        long j93 = j79 + (j88 & 5343);
        long j94 = j90 + (j89 >> 28);
        long j95 = j89 & M28L;
        long j96 = j91 + (j94 >> 28);
        long j97 = j94 & M28L;
        long j98 = j92 + (j96 >> 28);
        long j99 = j96 & M28L;
        long j100 = j93 + (j98 >> 28);
        long j101 = j98 & M28L;
        long j102 = j81 + (j100 >> 28);
        long j103 = j100 & M28L;
        long j104 = j83 + (j102 >> 28);
        long j105 = j102 & M28L;
        long j106 = j85 + (j104 >> 28);
        long j107 = j104 & M28L;
        long j108 = j87 + (j106 >> 28);
        long j109 = j106 & M28L;
        byte[] bArr2 = new byte[32];
        encode56(j95 | (j97 << 28), bArr2, 0);
        encode56(j99 | (j101 << 28), bArr2, 7);
        encode56(j103 | (j105 << 28), bArr2, 14);
        encode56(j107 | (j109 << 28), bArr2, 21);
        encode32((int) j108, bArr2, 28);
        return bArr2;
    }

    private static void scalarMult(byte[] bArr, PointAffine pointAffine, PointAccum pointAccum) {
        int[] iArr = new int[8];
        decodeScalar(bArr, 0, iArr);
        Nat.shiftDownBits(8, iArr, 3, 1);
        Nat.cadd(8, (iArr[0] ^ (-1)) & 1, iArr, f764L, iArr);
        Nat.shiftDownBit(8, iArr, 0);
        int[] pointPrecompute = pointPrecompute(pointAffine, 8);
        PointExt pointExt = new PointExt();
        pointCopy(pointAffine, pointAccum);
        pointLookup(pointPrecompute, 7, pointExt);
        pointAdd(pointExt, pointAccum);
        int i = 62;
        while (true) {
            pointLookup(iArr, i, pointPrecompute, pointExt);
            pointAdd(pointExt, pointAccum);
            pointDouble(pointAccum);
            pointDouble(pointAccum);
            pointDouble(pointAccum);
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointAccum);
        }
    }

    private static void scalarMultBase(byte[] bArr, PointAccum pointAccum) {
        precompute();
        int[] iArr = new int[8];
        decodeScalar(bArr, 0, iArr);
        Nat.cadd(8, (iArr[0] ^ (-1)) & 1, iArr, f764L, iArr);
        Nat.shiftDownBit(8, iArr, 1);
        for (int i = 0; i < 8; i++) {
            iArr[i] = Interleave.shuffle2(iArr[i]);
        }
        PointPrecomp pointPrecomp = new PointPrecomp();
        pointSetNeutral(pointAccum);
        int i2 = 28;
        while (true) {
            for (int i3 = 0; i3 < 8; i3++) {
                int i4 = iArr[i3] >>> i2;
                int i5 = (i4 >>> 3) & 1;
                pointLookup(i3, (i4 ^ (-i5)) & 7, pointPrecomp);
                C0322F.cswap(i5, pointPrecomp.ypx_h, pointPrecomp.ymx_h);
                C0322F.cnegate(i5, pointPrecomp.xyd);
                pointAddPrecomp(pointPrecomp, pointAccum);
            }
            i2 -= 4;
            if (i2 < 0) {
                return;
            }
            pointDouble(pointAccum);
        }
    }

    private static void scalarMultBaseEncoded(byte[] bArr, byte[] bArr2, int i) {
        PointAccum pointAccum = new PointAccum();
        scalarMultBase(bArr, pointAccum);
        if (0 == encodePoint(pointAccum, bArr2, i)) {
            throw new IllegalStateException();
        }
    }

    public static void scalarMultBaseYZ(X25519.Friend friend, byte[] bArr, int i, int[] iArr, int[] iArr2) {
        if (null == friend) {
            throw new NullPointerException("This method is only for use by X25519");
        }
        byte[] bArr2 = new byte[32];
        pruneScalar(bArr, i, bArr2);
        PointAccum pointAccum = new PointAccum();
        scalarMultBase(bArr2, pointAccum);
        if (0 == checkPoint(pointAccum.f770x, pointAccum.f771y, pointAccum.f772z)) {
            throw new IllegalStateException();
        }
        C0322F.copy(pointAccum.f771y, 0, iArr, 0);
        C0322F.copy(pointAccum.f772z, 0, iArr2, 0);
    }

    private static void scalarMultOrderVar(PointAffine pointAffine, PointAccum pointAccum) {
        byte[] wnafVar = getWnafVar(f764L, 5);
        PointExt[] pointPrecomputeVar = pointPrecomputeVar(pointCopy(pointAffine), 8);
        pointSetNeutral(pointAccum);
        int i = 252;
        while (true) {
            byte b = wnafVar[i];
            if (b != 0) {
                int i2 = b >> 31;
                pointAddVar(i2 != 0, pointPrecomputeVar[(b ^ i2) >>> 1], pointAccum);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointAccum);
        }
    }

    private static void scalarMultStrausVar(int[] iArr, int[] iArr2, PointAffine pointAffine, PointAccum pointAccum) {
        precompute();
        byte[] wnafVar = getWnafVar(iArr, 7);
        byte[] wnafVar2 = getWnafVar(iArr2, 5);
        PointExt[] pointPrecomputeVar = pointPrecomputeVar(pointCopy(pointAffine), 8);
        pointSetNeutral(pointAccum);
        int i = 252;
        while (true) {
            byte b = wnafVar[i];
            if (b != 0) {
                int i2 = b >> 31;
                pointAddVar(i2 != 0, precompBaseTable[(b ^ i2) >>> 1], pointAccum);
            }
            byte b2 = wnafVar2[i];
            if (b2 != 0) {
                int i3 = b2 >> 31;
                pointAddVar(i3 != 0, pointPrecomputeVar[(b2 ^ i3) >>> 1], pointAccum);
            }
            i--;
            if (i < 0) {
                return;
            }
            pointDouble(pointAccum);
        }
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, int i3, byte[] bArr3, int i4) {
        implSign(bArr, i, null, (byte) 0, bArr2, i2, i3, bArr3, i4);
    }

    public static void sign(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4, byte[] bArr4, int i5) {
        implSign(bArr, i, bArr2, i2, null, (byte) 0, bArr3, i3, i4, bArr4, i5);
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

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, Digest digest, byte[] bArr3, int i2) {
        byte[] bArr4 = new byte[64];
        if (64 != digest.doFinal(bArr4, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, (byte) 1, bArr4, 0, bArr4.length, bArr3, i2);
    }

    public static void signPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Digest digest, byte[] bArr4, int i3) {
        byte[] bArr5 = new byte[64];
        if (64 != digest.doFinal(bArr5, 0)) {
            throw new IllegalArgumentException("ph");
        }
        implSign(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr5, 0, bArr5.length, bArr4, i3);
    }

    public static boolean validatePublicKeyFull(byte[] bArr, int i) {
        PointAffine pointAffine = new PointAffine();
        if (decodePointVar(bArr, i, false, pointAffine)) {
            C0322F.normalize(pointAffine.f775x);
            C0322F.normalize(pointAffine.f776y);
            if (isNeutralElementVar(pointAffine.f775x, pointAffine.f776y)) {
                return false;
            }
            PointAccum pointAccum = new PointAccum();
            scalarMultOrderVar(pointAffine, pointAccum);
            C0322F.normalize(pointAccum.f770x);
            C0322F.normalize(pointAccum.f771y);
            C0322F.normalize(pointAccum.f772z);
            return isNeutralElementVar(pointAccum.f770x, pointAccum.f771y, pointAccum.f772z);
        }
        return false;
    }

    public static boolean validatePublicKeyPartial(byte[] bArr, int i) {
        return decodePointVar(bArr, i, false, new PointAffine());
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, null, (byte) 0, bArr3, i3, i4);
    }

    public static boolean verify(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3, int i4) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 0, bArr4, i3, i4);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, byte[] bArr4, int i3) {
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, i3, 64);
    }

    public static boolean verifyPrehash(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, Digest digest) {
        byte[] bArr4 = new byte[64];
        if (64 != digest.doFinal(bArr4, 0)) {
            throw new IllegalArgumentException("ph");
        }
        return implVerify(bArr, i, bArr2, i2, bArr3, (byte) 1, bArr4, 0, bArr4.length);
    }
}