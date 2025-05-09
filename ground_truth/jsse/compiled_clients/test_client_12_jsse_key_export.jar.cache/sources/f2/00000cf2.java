package org.bouncycastle.math.p010ec.rfc7748;

import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.rfc8032.Ed25519;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.rfc7748.X25519 */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X25519.class */
public abstract class X25519 {
    public static final int POINT_SIZE = 32;
    public static final int SCALAR_SIZE = 32;
    private static final int C_A = 486662;
    private static final int C_A24 = 121666;

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X25519$F */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X25519$F.class */
    private static class C0319F extends X25519Field {
        private C0319F() {
        }
    }

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X25519$Friend */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X25519$Friend.class */
    public static class Friend {
        private static final Friend INSTANCE = new Friend();

        private Friend() {
        }
    }

    public static boolean calculateAgreement(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        scalarMult(bArr, i, bArr2, i2, bArr3, i3);
        return !Arrays.areAllZeroes(bArr3, i3, 32);
    }

    private static int decode32(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16) | (bArr[i3 + 1] << 24);
    }

    private static void decodeScalar(byte[] bArr, int i, int[] iArr) {
        for (int i2 = 0; i2 < 8; i2++) {
            iArr[i2] = decode32(bArr, i + (i2 * 4));
        }
        iArr[0] = iArr[0] & (-8);
        iArr[7] = iArr[7] & Integer.MAX_VALUE;
        iArr[7] = iArr[7] | 1073741824;
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        secureRandom.nextBytes(bArr);
        bArr[0] = (byte) (bArr[0] & 248);
        bArr[31] = (byte) (bArr[31] & Byte.MAX_VALUE);
        bArr[31] = (byte) (bArr[31] | 64);
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        scalarMultBase(bArr, i, bArr2, i2);
    }

    private static void pointDouble(int[] iArr, int[] iArr2) {
        int[] create = C0319F.create();
        int[] create2 = C0319F.create();
        C0319F.apm(iArr, iArr2, create, create2);
        C0319F.sqr(create, create);
        C0319F.sqr(create2, create2);
        C0319F.mul(create, create2, iArr);
        C0319F.sub(create, create2, create);
        C0319F.mul(create, (int) C_A24, iArr2);
        C0319F.add(iArr2, create2, iArr2);
        C0319F.mul(iArr2, create, iArr2);
    }

    public static void precompute() {
        Ed25519.precompute();
    }

    public static void scalarMult(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        int[] iArr = new int[8];
        decodeScalar(bArr, i, iArr);
        int[] create = C0319F.create();
        C0319F.decode(bArr2, i2, create);
        int[] create2 = C0319F.create();
        C0319F.copy(create, 0, create2, 0);
        int[] create3 = C0319F.create();
        create3[0] = 1;
        int[] create4 = C0319F.create();
        create4[0] = 1;
        int[] create5 = C0319F.create();
        int[] create6 = C0319F.create();
        int[] create7 = C0319F.create();
        int i4 = 254;
        int i5 = 1;
        do {
            C0319F.apm(create4, create5, create6, create4);
            C0319F.apm(create2, create3, create5, create2);
            C0319F.mul(create6, create2, create6);
            C0319F.mul(create4, create5, create4);
            C0319F.sqr(create5, create5);
            C0319F.sqr(create2, create2);
            C0319F.sub(create5, create2, create7);
            C0319F.mul(create7, (int) C_A24, create3);
            C0319F.add(create3, create2, create3);
            C0319F.mul(create3, create7, create3);
            C0319F.mul(create2, create5, create2);
            C0319F.apm(create6, create4, create4, create5);
            C0319F.sqr(create4, create4);
            C0319F.sqr(create5, create5);
            C0319F.mul(create5, create, create5);
            i4--;
            int i6 = (iArr[i4 >>> 5] >>> (i4 & 31)) & 1;
            int i7 = i5 ^ i6;
            C0319F.cswap(i7, create2, create4);
            C0319F.cswap(i7, create3, create5);
            i5 = i6;
        } while (i4 >= 3);
        for (int i8 = 0; i8 < 3; i8++) {
            pointDouble(create2, create3);
        }
        C0319F.inv(create3, create3);
        C0319F.mul(create2, create3, create2);
        C0319F.normalize(create2);
        C0319F.encode(create2, bArr3, i3);
    }

    public static void scalarMultBase(byte[] bArr, int i, byte[] bArr2, int i2) {
        int[] create = C0319F.create();
        int[] create2 = C0319F.create();
        Ed25519.scalarMultBaseYZ(Friend.INSTANCE, bArr, i, create, create2);
        C0319F.apm(create2, create, create, create2);
        C0319F.inv(create2, create2);
        C0319F.mul(create, create2, create);
        C0319F.normalize(create);
        C0319F.encode(create, bArr2, i2);
    }
}