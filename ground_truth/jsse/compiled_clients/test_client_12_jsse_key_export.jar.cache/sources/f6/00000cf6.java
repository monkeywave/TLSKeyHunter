package org.bouncycastle.math.p010ec.rfc7748;

import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.rfc7748.X448 */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X448.class */
public abstract class X448 {
    public static final int POINT_SIZE = 56;
    public static final int SCALAR_SIZE = 56;
    private static final int C_A = 156326;
    private static final int C_A24 = 39082;

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X448$F */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X448$F.class */
    private static class C0320F extends X448Field {
        private C0320F() {
        }
    }

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X448$Friend */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/rfc7748/X448$Friend.class */
    public static class Friend {
        private static final Friend INSTANCE = new Friend();

        private Friend() {
        }
    }

    public static boolean calculateAgreement(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        scalarMult(bArr, i, bArr2, i2, bArr3, i3);
        return !Arrays.areAllZeroes(bArr3, i3, 56);
    }

    private static int decode32(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16) | (bArr[i3 + 1] << 24);
    }

    private static void decodeScalar(byte[] bArr, int i, int[] iArr) {
        for (int i2 = 0; i2 < 14; i2++) {
            iArr[i2] = decode32(bArr, i + (i2 * 4));
        }
        iArr[0] = iArr[0] & (-4);
        iArr[13] = iArr[13] | Integer.MIN_VALUE;
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        secureRandom.nextBytes(bArr);
        bArr[0] = (byte) (bArr[0] & 252);
        bArr[55] = (byte) (bArr[55] | 128);
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        scalarMultBase(bArr, i, bArr2, i2);
    }

    private static void pointDouble(int[] iArr, int[] iArr2) {
        int[] create = C0320F.create();
        int[] create2 = C0320F.create();
        C0320F.add(iArr, iArr2, create);
        C0320F.sub(iArr, iArr2, create2);
        C0320F.sqr(create, create);
        C0320F.sqr(create2, create2);
        C0320F.mul(create, create2, iArr);
        C0320F.sub(create, create2, create);
        C0320F.mul(create, (int) C_A24, iArr2);
        C0320F.add(iArr2, create2, iArr2);
        C0320F.mul(iArr2, create, iArr2);
    }

    public static void precompute() {
        Ed448.precompute();
    }

    public static void scalarMult(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        int[] iArr = new int[14];
        decodeScalar(bArr, i, iArr);
        int[] create = C0320F.create();
        C0320F.decode(bArr2, i2, create);
        int[] create2 = C0320F.create();
        C0320F.copy(create, 0, create2, 0);
        int[] create3 = C0320F.create();
        create3[0] = 1;
        int[] create4 = C0320F.create();
        create4[0] = 1;
        int[] create5 = C0320F.create();
        int[] create6 = C0320F.create();
        int[] create7 = C0320F.create();
        int i4 = 447;
        int i5 = 1;
        do {
            C0320F.add(create4, create5, create6);
            C0320F.sub(create4, create5, create4);
            C0320F.add(create2, create3, create5);
            C0320F.sub(create2, create3, create2);
            C0320F.mul(create6, create2, create6);
            C0320F.mul(create4, create5, create4);
            C0320F.sqr(create5, create5);
            C0320F.sqr(create2, create2);
            C0320F.sub(create5, create2, create7);
            C0320F.mul(create7, (int) C_A24, create3);
            C0320F.add(create3, create2, create3);
            C0320F.mul(create3, create7, create3);
            C0320F.mul(create2, create5, create2);
            C0320F.sub(create6, create4, create5);
            C0320F.add(create6, create4, create4);
            C0320F.sqr(create4, create4);
            C0320F.sqr(create5, create5);
            C0320F.mul(create5, create, create5);
            i4--;
            int i6 = (iArr[i4 >>> 5] >>> (i4 & 31)) & 1;
            int i7 = i5 ^ i6;
            C0320F.cswap(i7, create2, create4);
            C0320F.cswap(i7, create3, create5);
            i5 = i6;
        } while (i4 >= 2);
        for (int i8 = 0; i8 < 2; i8++) {
            pointDouble(create2, create3);
        }
        C0320F.inv(create3, create3);
        C0320F.mul(create2, create3, create2);
        C0320F.normalize(create2);
        C0320F.encode(create2, bArr3, i3);
    }

    public static void scalarMultBase(byte[] bArr, int i, byte[] bArr2, int i2) {
        int[] create = C0320F.create();
        int[] create2 = C0320F.create();
        Ed448.scalarMultBaseXY(Friend.INSTANCE, bArr, i, create, create2);
        C0320F.inv(create, create);
        C0320F.mul(create, create2, create);
        C0320F.sqr(create, create);
        C0320F.normalize(create);
        C0320F.encode(create, bArr2, i2);
    }
}