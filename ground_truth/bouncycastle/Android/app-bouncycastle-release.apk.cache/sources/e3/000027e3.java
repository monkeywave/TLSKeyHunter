package org.bouncycastle.math.raw;

/* loaded from: classes2.dex */
public abstract class Mont256 {

    /* renamed from: M */
    private static final long f1140M = 4294967295L;

    public static int inverse32(int i) {
        int i2 = (2 - (i * i)) * i;
        int i3 = i2 * (2 - (i * i2));
        int i4 = i3 * (2 - (i * i3));
        return i4 * (2 - (i * i4));
    }

    public static void multAdd(int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4, int i) {
        long j;
        char c = 0;
        long j2 = iArr2[0] & 4294967295L;
        int i2 = 0;
        int i3 = 0;
        while (i2 < 8) {
            long j3 = iArr[i2] & 4294967295L;
            long j4 = j3 * j2;
            long j5 = j2;
            long j6 = (((int) j) * i) & 4294967295L;
            int i4 = i2;
            int i5 = i3;
            long j7 = (iArr4[c] & 4294967295L) * j6;
            char c2 = ' ';
            long j8 = ((((j4 & 4294967295L) + (iArr3[c] & 4294967295L)) + (j7 & 4294967295L)) >>> 32) + (j4 >>> 32) + (j7 >>> 32);
            int i6 = 1;
            while (i6 < 8) {
                long j9 = (iArr2[i6] & 4294967295L) * j3;
                long j10 = (iArr4[i6] & 4294967295L) * j6;
                long j11 = j8 + (j9 & 4294967295L) + (j10 & 4294967295L) + (iArr3[i6] & 4294967295L);
                iArr3[i6 - 1] = (int) j11;
                j8 = (j11 >>> 32) + (j9 >>> 32) + (j10 >>> 32);
                i6++;
                c2 = ' ';
                j6 = j6;
            }
            long j12 = j8 + (i5 & 4294967295L);
            iArr3[7] = (int) j12;
            i3 = (int) (j12 >>> c2);
            i2 = i4 + 1;
            j2 = j5;
            c = 0;
        }
        if (i3 != 0 || Nat256.gte(iArr3, iArr4)) {
            Nat256.sub(iArr3, iArr4, iArr3);
        }
    }

    public static void multAddXF(int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        char c = 0;
        long j = iArr2[0] & 4294967295L;
        int i = 0;
        int i2 = 0;
        while (true) {
            if (i >= 8) {
                break;
            }
            long j2 = iArr[i] & 4294967295L;
            long j3 = (j2 * j) + (iArr3[c] & 4294967295L);
            long j4 = j3 & 4294967295L;
            long j5 = (j3 >>> 32) + j4;
            int i3 = 1;
            for (int i4 = 8; i3 < i4; i4 = 8) {
                long j6 = j;
                long j7 = (iArr2[i3] & 4294967295L) * j2;
                long j8 = (iArr4[i3] & 4294967295L) * j4;
                long j9 = j5 + (j7 & 4294967295L) + (j8 & 4294967295L) + (iArr3[i3] & 4294967295L);
                iArr3[i3 - 1] = (int) j9;
                j5 = (j9 >>> 32) + (j7 >>> 32) + (j8 >>> 32);
                i3++;
                j = j6;
                j2 = j2;
                j4 = j4;
            }
            long j10 = j5 + (i2 & 4294967295L);
            iArr3[7] = (int) j10;
            i2 = (int) (j10 >>> 32);
            i++;
            j = j;
            c = 0;
        }
        if (i2 != 0 || Nat256.gte(iArr3, iArr4)) {
            Nat256.sub(iArr3, iArr4, iArr3);
        }
    }

    public static void reduce(int[] iArr, int[] iArr2, int i) {
        int i2;
        char c = 0;
        int i3 = 0;
        while (i3 < 8) {
            long j = (i2 * i) & 4294967295L;
            long j2 = (((iArr2[c] & 4294967295L) * j) + (iArr[c] & 4294967295L)) >>> 32;
            int i4 = 1;
            while (i4 < 8) {
                long j3 = j2 + ((iArr2[i4] & 4294967295L) * j) + (iArr[i4] & 4294967295L);
                iArr[i4 - 1] = (int) j3;
                j2 = j3 >>> 32;
                i4++;
                i3 = i3;
            }
            iArr[7] = (int) j2;
            i3++;
            c = 0;
        }
        if (Nat256.gte(iArr, iArr2)) {
            Nat256.sub(iArr, iArr2, iArr);
        }
    }

    public static void reduceXF(int[] iArr, int[] iArr2) {
        for (int i = 0; i < 8; i++) {
            long j = iArr[0] & 4294967295L;
            long j2 = j;
            for (int i2 = 1; i2 < 8; i2++) {
                long j3 = j2 + ((iArr2[i2] & 4294967295L) * j) + (iArr[i2] & 4294967295L);
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