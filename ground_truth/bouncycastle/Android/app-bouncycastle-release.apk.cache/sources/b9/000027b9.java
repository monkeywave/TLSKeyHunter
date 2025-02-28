package org.bouncycastle.math.p016ec.rfc7748;

import java.security.SecureRandom;
import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.math.p016ec.rfc8032.Ed448;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.math.ec.rfc7748.X448 */
/* loaded from: classes2.dex */
public abstract class X448 {
    private static final int C_A = 156326;
    private static final int C_A24 = 39082;
    public static final int POINT_SIZE = 56;
    public static final int SCALAR_SIZE = 56;

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X448$F */
    /* loaded from: classes2.dex */
    private static class C1376F extends X448Field {
        private C1376F() {
        }
    }

    /* renamed from: org.bouncycastle.math.ec.rfc7748.X448$Friend */
    /* loaded from: classes2.dex */
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
        return (bArr[i + 3] << 24) | (bArr[i] & UByte.MAX_VALUE) | ((bArr[i + 1] & UByte.MAX_VALUE) << 8) | ((bArr[i + 2] & UByte.MAX_VALUE) << 16);
    }

    private static void decodeScalar(byte[] bArr, int i, int[] iArr) {
        for (int i2 = 0; i2 < 14; i2++) {
            iArr[i2] = decode32(bArr, (i2 * 4) + i);
        }
        iArr[0] = iArr[0] & (-4);
        iArr[13] = iArr[13] | Integer.MIN_VALUE;
    }

    public static void generatePrivateKey(SecureRandom secureRandom, byte[] bArr) {
        if (bArr.length != 56) {
            throw new IllegalArgumentException("k");
        }
        secureRandom.nextBytes(bArr);
        bArr[0] = (byte) (bArr[0] & 252);
        bArr[55] = (byte) (bArr[55] | ByteCompanionObject.MIN_VALUE);
    }

    public static void generatePublicKey(byte[] bArr, int i, byte[] bArr2, int i2) {
        scalarMultBase(bArr, i, bArr2, i2);
    }

    private static void pointDouble(int[] iArr, int[] iArr2) {
        int[] create = C1376F.create();
        int[] create2 = C1376F.create();
        C1376F.add(iArr, iArr2, create);
        C1376F.sub(iArr, iArr2, create2);
        C1376F.sqr(create, create);
        C1376F.sqr(create2, create2);
        C1376F.mul(create, create2, iArr);
        C1376F.sub(create, create2, create);
        C1376F.mul(create, (int) C_A24, iArr2);
        C1376F.add(iArr2, create2, iArr2);
        C1376F.mul(iArr2, create, iArr2);
    }

    public static void precompute() {
        Ed448.precompute();
    }

    public static void scalarMult(byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        int[] iArr = new int[14];
        decodeScalar(bArr, i, iArr);
        int[] create = C1376F.create();
        C1376F.decode(bArr2, i2, create);
        int[] create2 = C1376F.create();
        C1376F.copy(create, 0, create2, 0);
        int[] create3 = C1376F.create();
        create3[0] = 1;
        int[] create4 = C1376F.create();
        create4[0] = 1;
        int[] create5 = C1376F.create();
        int[] create6 = C1376F.create();
        int[] create7 = C1376F.create();
        int i4 = 447;
        int i5 = 1;
        while (true) {
            C1376F.add(create4, create5, create6);
            C1376F.sub(create4, create5, create4);
            C1376F.add(create2, create3, create5);
            C1376F.sub(create2, create3, create2);
            C1376F.mul(create6, create2, create6);
            C1376F.mul(create4, create5, create4);
            C1376F.sqr(create5, create5);
            C1376F.sqr(create2, create2);
            C1376F.sub(create5, create2, create7);
            C1376F.mul(create7, (int) C_A24, create3);
            C1376F.add(create3, create2, create3);
            C1376F.mul(create3, create7, create3);
            C1376F.mul(create2, create5, create2);
            C1376F.sub(create6, create4, create5);
            C1376F.add(create6, create4, create4);
            C1376F.sqr(create4, create4);
            C1376F.sqr(create5, create5);
            C1376F.mul(create5, create, create5);
            i4--;
            int i6 = (iArr[i4 >>> 5] >>> (i4 & 31)) & 1;
            int i7 = i5 ^ i6;
            C1376F.cswap(i7, create2, create4);
            C1376F.cswap(i7, create3, create5);
            if (i4 < 2) {
                break;
            }
            i5 = i6;
        }
        for (int i8 = 0; i8 < 2; i8++) {
            pointDouble(create2, create3);
        }
        C1376F.inv(create3, create3);
        C1376F.mul(create2, create3, create2);
        C1376F.normalize(create2);
        C1376F.encode(create2, bArr3, i3);
    }

    public static void scalarMultBase(byte[] bArr, int i, byte[] bArr2, int i2) {
        int[] create = C1376F.create();
        int[] create2 = C1376F.create();
        Ed448.scalarMultBaseXY(Friend.INSTANCE, bArr, i, create, create2);
        C1376F.inv(create, create);
        C1376F.mul(create, create2, create);
        C1376F.sqr(create, create);
        C1376F.normalize(create);
        C1376F.encode(create, bArr2, i2);
    }
}