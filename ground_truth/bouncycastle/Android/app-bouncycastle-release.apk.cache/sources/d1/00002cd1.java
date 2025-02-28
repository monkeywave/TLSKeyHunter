package org.bouncycastle.pqc.legacy.math.linearalgebra;

import kotlin.UByte;

/* loaded from: classes2.dex */
public final class BigEndianConversions {
    private BigEndianConversions() {
    }

    public static void I2OSP(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) (i >>> 24);
        bArr[i2 + 1] = (byte) (i >>> 16);
        bArr[i2 + 2] = (byte) (i >>> 8);
        bArr[i2 + 3] = (byte) i;
    }

    public static void I2OSP(int i, byte[] bArr, int i2, int i3) {
        int i4 = i3 - 1;
        for (int i5 = i4; i5 >= 0; i5--) {
            bArr[i2 + i5] = (byte) (i >>> ((i4 - i5) * 8));
        }
    }

    public static void I2OSP(long j, byte[] bArr, int i) {
        bArr[i] = (byte) (j >>> 56);
        bArr[i + 1] = (byte) (j >>> 48);
        bArr[i + 2] = (byte) (j >>> 40);
        bArr[i + 3] = (byte) (j >>> 32);
        bArr[i + 4] = (byte) (j >>> 24);
        bArr[i + 5] = (byte) (j >>> 16);
        bArr[i + 6] = (byte) (j >>> 8);
        bArr[i + 7] = (byte) j;
    }

    public static byte[] I2OSP(int i) {
        return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
    }

    public static byte[] I2OSP(int i, int i2) throws ArithmeticException {
        if (i < 0) {
            return null;
        }
        int ceilLog256 = IntegerFunctions.ceilLog256(i);
        if (ceilLog256 <= i2) {
            byte[] bArr = new byte[i2];
            int i3 = i2 - 1;
            for (int i4 = i3; i4 >= i2 - ceilLog256; i4--) {
                bArr[i4] = (byte) (i >>> ((i3 - i4) * 8));
            }
            return bArr;
        }
        throw new ArithmeticException("Cannot encode given integer into specified number of octets.");
    }

    public static byte[] I2OSP(long j) {
        return new byte[]{(byte) (j >>> 56), (byte) (j >>> 48), (byte) (j >>> 40), (byte) (j >>> 32), (byte) (j >>> 24), (byte) (j >>> 16), (byte) (j >>> 8), (byte) j};
    }

    public static int OS2IP(byte[] bArr) {
        if (bArr.length <= 4) {
            if (bArr.length == 0) {
                return 0;
            }
            int i = 0;
            for (int i2 = 0; i2 < bArr.length; i2++) {
                i |= (bArr[i2] & UByte.MAX_VALUE) << (((bArr.length - 1) - i2) * 8);
            }
            return i;
        }
        throw new ArithmeticException("invalid input length");
    }

    public static int OS2IP(byte[] bArr, int i) {
        int i2 = i + 2;
        int i3 = (bArr[i + 1] & UByte.MAX_VALUE) << 16;
        return (bArr[i + 3] & UByte.MAX_VALUE) | i3 | ((bArr[i] & UByte.MAX_VALUE) << 24) | ((bArr[i2] & UByte.MAX_VALUE) << 8);
    }

    public static int OS2IP(byte[] bArr, int i, int i2) {
        if (bArr.length == 0 || bArr.length < (i + i2) - 1) {
            return 0;
        }
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            i3 |= (bArr[i + i4] & 255) << (((i2 - i4) - 1) * 8);
        }
        return i3;
    }

    public static long OS2LIP(byte[] bArr, int i) {
        long j = ((bArr[i] & 255) << 56) | ((bArr[i + 1] & 255) << 48) | ((bArr[i + 2] & 255) << 40) | ((bArr[i + 3] & 255) << 32) | ((255 & bArr[i + 4]) << 24);
        int i2 = i + 6;
        return (bArr[i + 7] & UByte.MAX_VALUE) | j | ((bArr[i + 5] & UByte.MAX_VALUE) << 16) | ((bArr[i2] & UByte.MAX_VALUE) << 8);
    }

    public static byte[] toByteArray(int[] iArr) {
        byte[] bArr = new byte[iArr.length << 2];
        for (int i = 0; i < iArr.length; i++) {
            I2OSP(iArr[i], bArr, i << 2);
        }
        return bArr;
    }

    public static byte[] toByteArray(int[] iArr, int i) {
        int length = iArr.length;
        byte[] bArr = new byte[i];
        int i2 = 0;
        int i3 = 0;
        while (i2 <= length - 2) {
            I2OSP(iArr[i2], bArr, i3);
            i2++;
            i3 += 4;
        }
        I2OSP(iArr[length - 1], bArr, i3, i - i3);
        return bArr;
    }

    public static int[] toIntArray(byte[] bArr) {
        int length = (bArr.length + 3) / 4;
        int length2 = bArr.length & 3;
        int[] iArr = new int[length];
        int i = 0;
        int i2 = 0;
        while (i <= length - 2) {
            iArr[i] = OS2IP(bArr, i2);
            i++;
            i2 += 4;
        }
        int i3 = length - 1;
        if (length2 != 0) {
            iArr[i3] = OS2IP(bArr, i2, length2);
        } else {
            iArr[i3] = OS2IP(bArr, i2);
        }
        return iArr;
    }
}