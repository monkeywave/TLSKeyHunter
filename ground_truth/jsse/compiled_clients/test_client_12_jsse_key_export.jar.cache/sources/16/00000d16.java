package org.bouncycastle.math.raw;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/raw/Mont256.class */
public abstract class Mont256 {

    /* renamed from: M */
    private static final long f789M = 4294967295L;

    public static int inverse32(int i) {
        int i2 = i * (2 - (i * i));
        int i3 = i2 * (2 - (i * i2));
        int i4 = i3 * (2 - (i * i3));
        return i4 * (2 - (i * i4));
    }

    public static void multAdd(int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4, int i) {
        int i2 = 0;
        long j = iArr2[0] & f789M;
        for (int i3 = 0; i3 < 8; i3++) {
            long j2 = iArr3[0] & f789M;
            long j3 = iArr[i3] & f789M;
            long j4 = j3 * j;
            long j5 = (j4 & f789M) + j2;
            long j6 = (((int) j5) * i) & f789M;
            long j7 = j6 * (iArr4[0] & f789M);
            long j8 = ((j5 + (j7 & f789M)) >>> 32) + (j4 >>> 32) + (j7 >>> 32);
            for (int i4 = 1; i4 < 8; i4++) {
                long j9 = j3 * (iArr2[i4] & f789M);
                long j10 = j6 * (iArr4[i4] & f789M);
                long j11 = j8 + (j9 & f789M) + (j10 & f789M) + (iArr3[i4] & f789M);
                iArr3[i4 - 1] = (int) j11;
                j8 = (j11 >>> 32) + (j9 >>> 32) + (j10 >>> 32);
            }
            long j12 = j8 + (i2 & f789M);
            iArr3[7] = (int) j12;
            i2 = (int) (j12 >>> 32);
        }
        if (i2 != 0 || Nat256.gte(iArr3, iArr4)) {
            Nat256.sub(iArr3, iArr4, iArr3);
        }
    }

    public static void multAddXF(int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int i = 0;
        long j = iArr2[0] & f789M;
        for (int i2 = 0; i2 < 8; i2++) {
            long j2 = iArr[i2] & f789M;
            long j3 = (j2 * j) + (iArr3[0] & f789M);
            long j4 = j3 & f789M;
            long j5 = (j3 >>> 32) + j4;
            for (int i3 = 1; i3 < 8; i3++) {
                long j6 = j2 * (iArr2[i3] & f789M);
                long j7 = j4 * (iArr4[i3] & f789M);
                long j8 = j5 + (j6 & f789M) + (j7 & f789M) + (iArr3[i3] & f789M);
                iArr3[i3 - 1] = (int) j8;
                j5 = (j8 >>> 32) + (j6 >>> 32) + (j7 >>> 32);
            }
            long j9 = j5 + (i & f789M);
            iArr3[7] = (int) j9;
            i = (int) (j9 >>> 32);
        }
        if (i != 0 || Nat256.gte(iArr3, iArr4)) {
            Nat256.sub(iArr3, iArr4, iArr3);
        }
    }

    public static void reduce(int[] iArr, int[] iArr2, int i) {
        for (int i2 = 0; i2 < 8; i2++) {
            int i3 = iArr[0];
            long j = (i3 * i) & f789M;
            long j2 = ((j * (iArr2[0] & f789M)) + (i3 & f789M)) >>> 32;
            for (int i4 = 1; i4 < 8; i4++) {
                long j3 = j2 + (j * (iArr2[i4] & f789M)) + (iArr[i4] & f789M);
                iArr[i4 - 1] = (int) j3;
                j2 = j3 >>> 32;
            }
            iArr[7] = (int) j2;
        }
        if (Nat256.gte(iArr, iArr2)) {
            Nat256.sub(iArr, iArr2, iArr);
        }
    }

    public static void reduceXF(int[] iArr, int[] iArr2) {
        for (int i = 0; i < 8; i++) {
            long j = iArr[0] & f789M;
            long j2 = j;
            for (int i2 = 1; i2 < 8; i2++) {
                long j3 = j2 + (j * (iArr2[i2] & f789M)) + (iArr[i2] & f789M);
                iArr[i2 - 1] = (int) j3;
                j2 = j3 >>> 32;
            }
            iArr[7] = (int) j2;
        }
        if (Nat256.gte(iArr, iArr2)) {
            Nat256.sub(iArr, iArr2, iArr);
        }
    }
}