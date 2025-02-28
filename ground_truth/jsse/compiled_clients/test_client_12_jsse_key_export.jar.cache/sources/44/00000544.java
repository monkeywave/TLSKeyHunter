package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DESParameters.class */
public class DESParameters extends KeyParameter {
    public static final int DES_KEY_LENGTH = 8;
    private static final int N_DES_WEAK_KEYS = 16;
    private static byte[] DES_weak_keys = {1, 1, 1, 1, 1, 1, 1, 1, 31, 31, 31, 31, 14, 14, 14, 14, -32, -32, -32, -32, -15, -15, -15, -15, -2, -2, -2, -2, -2, -2, -2, -2, 1, -2, 1, -2, 1, -2, 1, -2, 31, -32, 31, -32, 14, -15, 14, -15, 1, -32, 1, -32, 1, -15, 1, -15, 31, -2, 31, -2, 14, -2, 14, -2, 1, 31, 1, 31, 1, 14, 1, 14, -32, -2, -32, -2, -15, -2, -15, -2, -2, 1, -2, 1, -2, 1, -2, 1, -32, 31, -32, 31, -15, 14, -15, 14, -32, 1, -32, 1, -15, 1, -15, 1, -2, 31, -2, 31, -2, 14, -2, 14, 31, 1, 31, 1, 14, 1, 14, 1, -2, -32, -2, -32, -2, -15, -2, -15};

    public DESParameters(byte[] bArr) {
        super(bArr);
        if (isWeakKey(bArr, 0)) {
            throw new IllegalArgumentException("attempt to create weak DES key");
        }
    }

    /* JADX WARN: Code restructure failed: missing block: B:18:0x0040, code lost:
        r7 = r7 + 1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public static boolean isWeakKey(byte[] r5, int r6) {
        /*
            r0 = r5
            int r0 = r0.length
            r1 = r6
            int r0 = r0 - r1
            r1 = 8
            if (r0 >= r1) goto L13
            java.lang.IllegalArgumentException r0 = new java.lang.IllegalArgumentException
            r1 = r0
            java.lang.String r2 = "key material too short."
            r1.<init>(r2)
            throw r0
        L13:
            r0 = 0
            r7 = r0
        L15:
            r0 = r7
            r1 = 16
            if (r0 >= r1) goto L46
            r0 = 0
            r8 = r0
        L1d:
            r0 = r8
            r1 = 8
            if (r0 >= r1) goto L3e
            r0 = r5
            r1 = r8
            r2 = r6
            int r1 = r1 + r2
            r0 = r0[r1]
            byte[] r1 = org.bouncycastle.crypto.params.DESParameters.DES_weak_keys
            r2 = r7
            r3 = 8
            int r2 = r2 * r3
            r3 = r8
            int r2 = r2 + r3
            r1 = r1[r2]
            if (r0 == r1) goto L38
            goto L40
        L38:
            int r8 = r8 + 1
            goto L1d
        L3e:
            r0 = 1
            return r0
        L40:
            int r7 = r7 + 1
            goto L15
        L46:
            r0 = 0
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.crypto.params.DESParameters.isWeakKey(byte[], int):boolean");
    }

    public static void setOddParity(byte[] bArr) {
        for (int i = 0; i < bArr.length; i++) {
            byte b = bArr[i];
            bArr[i] = (byte) ((b & 254) | (((((((((b >> 1) ^ (b >> 2)) ^ (b >> 3)) ^ (b >> 4)) ^ (b >> 5)) ^ (b >> 6)) ^ (b >> 7)) ^ 1) & 1));
        }
    }
}