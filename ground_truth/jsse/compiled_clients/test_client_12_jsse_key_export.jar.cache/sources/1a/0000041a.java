package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/XofUtils.class */
public class XofUtils {
    public static byte[] leftEncode(long j) {
        byte b = 1;
        long j2 = j;
        while (true) {
            long j3 = j2 >> 8;
            j2 = j3;
            if (j3 == 0) {
                break;
            }
            b = (byte) (b + 1);
        }
        byte[] bArr = new byte[b + 1];
        bArr[0] = b;
        for (int i = 1; i <= b; i++) {
            bArr[i] = (byte) (j >> (8 * (b - i)));
        }
        return bArr;
    }

    public static byte[] rightEncode(long j) {
        byte b = 1;
        long j2 = j;
        while (true) {
            long j3 = j2 >> 8;
            j2 = j3;
            if (j3 == 0) {
                break;
            }
            b = (byte) (b + 1);
        }
        byte[] bArr = new byte[b + 1];
        bArr[b] = b;
        for (int i = 0; i < b; i++) {
            bArr[i] = (byte) (j >> (8 * ((b - i) - 1)));
        }
        return bArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encode(byte b) {
        return Arrays.concatenate(leftEncode(8L), new byte[]{b});
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] encode(byte[] bArr, int i, int i2) {
        return bArr.length == i2 ? Arrays.concatenate(leftEncode(i2 * 8), bArr) : Arrays.concatenate(leftEncode(i2 * 8), Arrays.copyOfRange(bArr, i, i + i2));
    }
}