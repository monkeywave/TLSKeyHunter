package org.bouncycastle.pqc.crypto.newhope;

import com.google.android.material.internal.ViewUtils;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class ErrorCorrection {
    ErrorCorrection() {
    }

    static short LDDecode(int i, int i2, int i3, int i4) {
        return (short) (((((m23g(i) + m23g(i2)) + m23g(i3)) + m23g(i4)) - 98312) >>> 31);
    }

    static int abs(int i) {
        int i2 = i >> 31;
        return (i ^ i2) - i2;
    }

    /* renamed from: f */
    static int m24f(int[] iArr, int i, int i2, int i3) {
        int i4 = (i3 * 2730) >> 25;
        int i5 = i4 - ((12288 - (i3 - (i4 * 12289))) >> 31);
        iArr[i] = (i5 >> 1) + (i5 & 1);
        int i6 = i5 - 1;
        iArr[i2] = (i6 >> 1) + (i6 & 1);
        return abs(i3 - (iArr[i] * 24578));
    }

    /* renamed from: g */
    static int m23g(int i) {
        int i2 = (i * 2730) >> 27;
        int i3 = i2 - ((CipherSuite.TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA - (i - (CipherSuite.TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA * i2))) >> 31);
        return abs((((i3 >> 1) + (i3 & 1)) * 98312) - i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void helpRec(short[] sArr, short[] sArr2, byte[] bArr, byte b) {
        short s = 8;
        byte[] bArr2 = new byte[8];
        bArr2[0] = b;
        byte[] bArr3 = new byte[32];
        ChaCha20.process(bArr, bArr2, bArr3, 0, 32);
        int[] iArr = new int[8];
        int i = 0;
        while (i < 256) {
            int i2 = ((bArr3[i >>> 3] >>> (i & 7)) & 1) * 4;
            int i3 = i + 256;
            int i4 = i + 512;
            int m24f = m24f(iArr, 0, 4, (sArr2[i] * s) + i2) + m24f(iArr, 1, 5, (sArr2[i3] * s) + i2) + m24f(iArr, 2, 6, (sArr2[i4] * s) + i2);
            int i5 = i + ViewUtils.EDGE_TO_EDGE_FLAGS;
            int m24f2 = (24577 - (m24f + m24f(iArr, 3, 7, (sArr2[i5] * s) + i2))) >> 31;
            int i6 = ~m24f2;
            int[] iArr2 = {(i6 & iArr[0]) ^ (iArr[4] & m24f2), (i6 & iArr[1]) ^ (iArr[5] & m24f2), (i6 & iArr[2]) ^ (iArr[6] & m24f2), (iArr[7] & m24f2) ^ (i6 & iArr[3])};
            int i7 = iArr2[0];
            int i8 = iArr2[3];
            sArr[i] = (short) ((i7 - i8) & 3);
            sArr[i3] = (short) ((iArr2[1] - i8) & 3);
            sArr[i4] = (short) ((iArr2[2] - i8) & 3);
            sArr[i5] = (short) (((-m24f2) + (i8 * 2)) & 3);
            i++;
            s = 8;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void rec(byte[] bArr, short[] sArr, short[] sArr2) {
        Arrays.fill(bArr, (byte) 0);
        for (int i = 0; i < 256; i++) {
            int i2 = i + ViewUtils.EDGE_TO_EDGE_FLAGS;
            short s = sArr2[i2];
            int i3 = ((sArr[i] * 8) + 196624) - (((sArr2[i] * 2) + s) * 12289);
            int i4 = i + 256;
            int i5 = ((sArr[i4] * 8) + 196624) - (((sArr2[i4] * 2) + s) * 12289);
            int i6 = i + 512;
            int[] iArr = {i3, i5, ((sArr[i6] * 8) + 196624) - (((sArr2[i6] * 2) + s) * 12289), ((sArr[i2] * 8) + 196624) - (s * 12289)};
            int i7 = i >>> 3;
            bArr[i7] = (byte) ((LDDecode(iArr[0], iArr[1], iArr[2], iArr[3]) << (i & 7)) | bArr[i7]);
        }
    }
}