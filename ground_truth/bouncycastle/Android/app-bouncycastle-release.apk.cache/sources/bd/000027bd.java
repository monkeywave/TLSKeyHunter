package org.bouncycastle.math.p016ec.rfc8032;

import kotlin.UByte;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Codec */
/* loaded from: classes2.dex */
abstract class Codec {
    Codec() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int decode16(byte[] bArr, int i) {
        return ((bArr[i + 1] & UByte.MAX_VALUE) << 8) | (bArr[i] & UByte.MAX_VALUE);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int decode24(byte[] bArr, int i) {
        return ((bArr[i + 2] & UByte.MAX_VALUE) << 16) | (bArr[i] & UByte.MAX_VALUE) | ((bArr[i + 1] & UByte.MAX_VALUE) << 8);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int decode32(byte[] bArr, int i) {
        return (bArr[i + 3] << 24) | (bArr[i] & UByte.MAX_VALUE) | ((bArr[i + 1] & UByte.MAX_VALUE) << 8) | ((bArr[i + 2] & UByte.MAX_VALUE) << 16);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void decode32(byte[] bArr, int i, int[] iArr, int i2, int i3) {
        for (int i4 = 0; i4 < i3; i4++) {
            iArr[i2 + i4] = decode32(bArr, (i4 * 4) + i);
        }
    }

    static void encode24(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2 + 2] = (byte) (i >>> 16);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encode32(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 3] = (byte) (i >>> 24);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encode32(int[] iArr, int i, int i2, byte[] bArr, int i3) {
        for (int i4 = 0; i4 < i2; i4++) {
            encode32(iArr[i + i4], bArr, (i4 * 4) + i3);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void encode56(long j, byte[] bArr, int i) {
        encode32((int) j, bArr, i);
        encode24((int) (j >>> 32), bArr, i + 4);
    }
}