package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.asn1.cmc.BodyPartID;

/* loaded from: classes2.dex */
abstract class BENES {
    private static final long[] TRANSPOSE_MASKS = {6148914691236517205L, 3689348814741910323L, 1085102592571150095L, 71777214294589695L, 281470681808895L, BodyPartID.bodyIdMax};
    protected final int GFBITS;
    protected final int SYS_N;
    protected final int SYS_T;

    public BENES(int i, int i2, int i3) {
        this.SYS_N = i;
        this.SYS_T = i2;
        this.GFBITS = i3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void transpose_64x64(long[] jArr, long[] jArr2) {
        transpose_64x64(jArr, jArr2, 0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void transpose_64x64(long[] jArr, long[] jArr2, int i) {
        int i2;
        System.arraycopy(jArr2, i, jArr, i, 64);
        int i3 = 5;
        do {
            long j = TRANSPOSE_MASKS[i3];
            int i4 = 1 << i3;
            int i5 = i;
            while (true) {
                i2 = i + 64;
                if (i5 >= i2) {
                    break;
                }
                for (int i6 = i5; i6 < i5 + i4; i6 += 4) {
                    long j2 = jArr[i6];
                    int i7 = i6 + 1;
                    long j3 = jArr[i7];
                    int i8 = i6 + 2;
                    long j4 = jArr[i8];
                    int i9 = i6 + 3;
                    long j5 = jArr[i9];
                    int i10 = i6 + i4;
                    long j6 = jArr[i10];
                    int i11 = i10 + 1;
                    long j7 = jArr[i11];
                    int i12 = i10 + 2;
                    long j8 = jArr[i12];
                    int i13 = i10 + 3;
                    long j9 = jArr[i13];
                    long j10 = ((j2 >>> i4) ^ j6) & j;
                    long j11 = ((j3 >>> i4) ^ j7) & j;
                    long j12 = ((j4 >>> i4) ^ j8) & j;
                    long j13 = ((j5 >>> i4) ^ j9) & j;
                    jArr[i6] = j2 ^ (j10 << i4);
                    jArr[i7] = (j11 << i4) ^ j3;
                    jArr[i8] = (j12 << i4) ^ j4;
                    jArr[i9] = j5 ^ (j13 << i4);
                    jArr[i10] = j6 ^ j10;
                    jArr[i11] = j7 ^ j11;
                    jArr[i12] = j8 ^ j12;
                    jArr[i13] = j9 ^ j13;
                }
                i5 += i4 * 2;
            }
            i3--;
        } while (i3 >= 2);
        do {
            long j14 = TRANSPOSE_MASKS[i3];
            int i14 = 1 << i3;
            for (int i15 = i; i15 < i2; i15 += i14 * 2) {
                for (int i16 = i15; i16 < i15 + i14; i16++) {
                    long j15 = jArr[i16];
                    int i17 = i16 + i14;
                    long j16 = jArr[i17];
                    long j17 = ((j15 >>> i14) ^ j16) & j14;
                    jArr[i16] = j15 ^ (j17 << i14);
                    jArr[i17] = j16 ^ j17;
                }
            }
            i3--;
        } while (i3 >= 0);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public abstract void support_gen(short[] sArr, byte[] bArr);
}