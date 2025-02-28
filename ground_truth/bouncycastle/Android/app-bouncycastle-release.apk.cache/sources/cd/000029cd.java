package org.bouncycastle.pqc.crypto.hqc;

import androidx.core.internal.view.SupportMenu;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class ReedMuller {

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public static class Codeword {
        int[] type32 = new int[4];
        int[] type8 = new int[16];
    }

    ReedMuller() {
    }

    private static int Bit0Mask(int i) {
        return -(i & 1);
    }

    public static void decode(byte[] bArr, long[] jArr, int i, int i2) {
        byte[] clone = Arrays.clone(bArr);
        int length = jArr.length / 2;
        Codeword[] codewordArr = new Codeword[length];
        int[] iArr = new int[jArr.length * 2];
        Utils.fromLongArrayToByte32Array(iArr, jArr);
        for (int i3 = 0; i3 < length; i3++) {
            codewordArr[i3] = new Codeword();
            for (int i4 = 0; i4 < 4; i4++) {
                codewordArr[i3].type32[i4] = iArr[(i3 * 4) + i4];
            }
        }
        int[] iArr2 = new int[128];
        for (int i5 = 0; i5 < i; i5++) {
            expandThenSum(iArr2, codewordArr, i5 * i2, i2);
            int[] iArr3 = new int[128];
            hadamardTransform(iArr2, iArr3);
            iArr3[0] = iArr3[0] - (i2 * 64);
            clone[i5] = (byte) findPeaks(iArr3);
        }
        int[] iArr4 = new int[length * 4];
        int i6 = 0;
        for (int i7 = 0; i7 < length; i7++) {
            System.arraycopy(codewordArr[i7].type32, 0, iArr4, i6, codewordArr[i7].type32.length);
            i6 += 4;
        }
        Utils.fromByte32ArrayToLongArray(jArr, iArr4);
        System.arraycopy(clone, 0, bArr, 0, bArr.length);
    }

    public static void encode(long[] jArr, byte[] bArr, int i, int i2) {
        byte[] clone = Arrays.clone(bArr);
        int i3 = i * i2;
        Codeword[] codewordArr = new Codeword[i3];
        for (int i4 = 0; i4 < i3; i4++) {
            codewordArr[i4] = new Codeword();
        }
        for (int i5 = 0; i5 < i; i5++) {
            int i6 = i5 * i2;
            encodeSub(codewordArr[i6], clone[i5]);
            for (int i7 = 1; i7 < i2; i7++) {
                codewordArr[i6 + i7] = codewordArr[i6];
            }
        }
        int[] iArr = new int[i3 * 4];
        int i8 = 0;
        for (int i9 = 0; i9 < i3; i9++) {
            System.arraycopy(codewordArr[i9].type32, 0, iArr, i8, codewordArr[i9].type32.length);
            i8 += 4;
        }
        Utils.fromByte32ArrayToLongArray(jArr, iArr);
    }

    static void encodeSub(Codeword codeword, int i) {
        int Bit0Mask = ((((Bit0Mask(i >> 7) ^ (Bit0Mask(i) & (-1431655766))) ^ (Bit0Mask(i >> 1) & (-858993460))) ^ (Bit0Mask(i >> 2) & (-252645136))) ^ (Bit0Mask(i >> 3) & (-16711936))) ^ (Bit0Mask(i >> 4) & SupportMenu.CATEGORY_MASK);
        codeword.type32[0] = Bit0Mask;
        int i2 = i >> 5;
        int Bit0Mask2 = Bit0Mask ^ Bit0Mask(i2);
        codeword.type32[1] = Bit0Mask2;
        int Bit0Mask3 = Bit0Mask(i >> 6) ^ Bit0Mask2;
        codeword.type32[3] = Bit0Mask3;
        codeword.type32[2] = Bit0Mask3 ^ Bit0Mask(i2);
    }

    private static void expandThenSum(int[] iArr, Codeword[] codewordArr, int i, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            for (int i4 = 0; i4 < 32; i4++) {
                int i5 = codewordArr[i].type32[i3];
                iArr[(i3 * 32) + i4] = (codewordArr[i].type32[i3] >> i4) & 1;
            }
        }
        for (int i6 = 1; i6 < i2; i6++) {
            for (int i7 = 0; i7 < 4; i7++) {
                for (int i8 = 0; i8 < 32; i8++) {
                    int i9 = (i7 * 32) + i8;
                    iArr[i9] = iArr[i9] + ((codewordArr[i6 + i].type32[i7] >> i8) & 1);
                }
            }
        }
    }

    private static int findPeaks(int[] iArr) {
        int i = 0;
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < 128; i4++) {
            int i5 = iArr[i4];
            int i6 = i5 > 0 ? -1 : 0;
            int i7 = ((~i6) & (-i5)) | (i6 & i5);
            if (i7 > i3) {
                i = i5;
            }
            if (i7 > i3) {
                i2 = i4;
            }
            if (i7 > i3) {
                i3 = i7;
            }
        }
        return i2 | ((i > 0 ? 1 : 0) * 128);
    }

    private static void hadamardTransform(int[] iArr, int[] iArr2) {
        int[] clone = Arrays.clone(iArr);
        int[] clone2 = Arrays.clone(iArr2);
        int i = 0;
        while (true) {
            int[] iArr3 = clone2;
            clone2 = clone;
            clone = iArr3;
            if (i >= 7) {
                System.arraycopy(clone, 0, iArr, 0, iArr.length);
                System.arraycopy(clone2, 0, iArr2, 0, iArr2.length);
                return;
            }
            for (int i2 = 0; i2 < 64; i2++) {
                int i3 = i2 * 2;
                int i4 = i3 + 1;
                clone[i2] = clone2[i3] + clone2[i4];
                clone[i2 + 64] = clone2[i3] - clone2[i4];
            }
            i++;
        }
    }
}