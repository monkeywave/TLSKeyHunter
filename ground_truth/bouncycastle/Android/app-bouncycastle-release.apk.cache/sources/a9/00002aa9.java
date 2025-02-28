package org.bouncycastle.pqc.crypto.sphincs;

import kotlin.UByte;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class Wots {
    static final int WOTS_L = 67;
    static final int WOTS_L1 = 64;
    static final int WOTS_LOGW = 4;
    static final int WOTS_LOG_L = 7;
    static final int WOTS_SIGBYTES = 2144;
    static final int WOTS_W = 16;

    private static void clear(byte[] bArr, int i, int i2) {
        for (int i3 = 0; i3 != i2; i3++) {
            bArr[i3 + i] = 0;
        }
    }

    static void expand_seed(byte[] bArr, int i, byte[] bArr2, int i2) {
        clear(bArr, i, WOTS_SIGBYTES);
        Seed.prg(bArr, i, 2144L, bArr2, i2);
    }

    static void gen_chain(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3, int i4) {
        for (int i5 = 0; i5 < 32; i5++) {
            bArr[i5 + i] = bArr2[i5 + i2];
        }
        for (int i6 = 0; i6 < i4 && i6 < 16; i6++) {
            hashFunctions.hash_n_n_mask(bArr, i, bArr, i, bArr3, i3 + (i6 * 32));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void wots_pkgen(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, int i2, byte[] bArr3, int i3) {
        expand_seed(bArr, i, bArr2, i2);
        for (int i4 = 0; i4 < 67; i4++) {
            int i5 = i + (i4 * 32);
            gen_chain(hashFunctions, bArr, i5, bArr, i5, bArr3, i3, 15);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void wots_sign(HashFunctions hashFunctions, byte[] bArr, int i, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        int[] iArr = new int[67];
        int i2 = 0;
        int i3 = 0;
        while (i2 < 64) {
            byte b = bArr2[i2 / 2];
            iArr[i2] = b & 15;
            int i4 = (b & UByte.MAX_VALUE) >>> 4;
            iArr[i2 + 1] = i4;
            i3 = i3 + (15 - iArr[i2]) + (15 - i4);
            i2 += 2;
        }
        while (i2 < 67) {
            iArr[i2] = i3 & 15;
            i3 >>>= 4;
            i2++;
        }
        expand_seed(bArr, i, bArr3, 0);
        for (int i5 = 0; i5 < 67; i5++) {
            int i6 = i + (i5 * 32);
            gen_chain(hashFunctions, bArr, i6, bArr, i6, bArr4, 0, iArr[i5]);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void wots_verify(HashFunctions hashFunctions, byte[] bArr, byte[] bArr2, int i, byte[] bArr3, byte[] bArr4) {
        int[] iArr = new int[67];
        int i2 = 0;
        int i3 = 0;
        while (i2 < 64) {
            byte b = bArr3[i2 / 2];
            iArr[i2] = b & 15;
            int i4 = (b & UByte.MAX_VALUE) >>> 4;
            iArr[i2 + 1] = i4;
            i3 = i3 + (15 - iArr[i2]) + (15 - i4);
            i2 += 2;
        }
        while (i2 < 67) {
            iArr[i2] = i3 & 15;
            i3 >>>= 4;
            i2++;
        }
        for (int i5 = 0; i5 < 67; i5++) {
            int i6 = i5 * 32;
            int i7 = iArr[i5];
            gen_chain(hashFunctions, bArr, i6, bArr2, i + i6, bArr4, i7 * 32, 15 - i7);
        }
    }
}