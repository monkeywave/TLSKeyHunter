package org.bouncycastle.math.p016ec.rfc8032;

/* renamed from: org.bouncycastle.math.ec.rfc8032.Wnaf */
/* loaded from: classes2.dex */
abstract class Wnaf {
    Wnaf() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getSignedVar(int[] iArr, int i, byte[] bArr) {
        int length = iArr.length * 2;
        int[] iArr2 = new int[length];
        int i2 = iArr[iArr.length - 1] >> 31;
        int length2 = iArr.length;
        int i3 = length;
        while (true) {
            length2--;
            if (length2 < 0) {
                break;
            }
            int i4 = iArr[length2];
            iArr2[i3 - 1] = (i2 << 16) | (i4 >>> 16);
            i3 -= 2;
            iArr2[i3] = i4;
            i2 = i4;
        }
        int i5 = 32 - i;
        int i6 = 0;
        int i7 = 0;
        int i8 = 0;
        while (i6 < length) {
            int i9 = iArr2[i6];
            while (i7 < 16) {
                int i10 = i9 >>> i7;
                if ((i10 & 1) == i8) {
                    i7++;
                } else {
                    int i11 = (i10 | 1) << i5;
                    bArr[(i6 << 4) + i7] = (byte) (i11 >> i5);
                    i7 += i;
                    i8 = i11 >>> 31;
                }
            }
            i6++;
            i7 -= 16;
        }
    }
}