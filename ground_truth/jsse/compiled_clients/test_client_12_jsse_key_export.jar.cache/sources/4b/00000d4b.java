package org.bouncycastle.pqc.crypto.gmss.util;

import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/gmss/util/GMSSUtil.class */
public class GMSSUtil {
    public byte[] intToBytesLittleEndian(int i) {
        return new byte[]{(byte) (i & GF2Field.MASK), (byte) ((i >> 8) & GF2Field.MASK), (byte) ((i >> 16) & GF2Field.MASK), (byte) ((i >> 24) & GF2Field.MASK)};
    }

    public int bytesToIntLittleEndian(byte[] bArr) {
        return (bArr[0] & 255) | ((bArr[1] & 255) << 8) | ((bArr[2] & 255) << 16) | ((bArr[3] & 255) << 24);
    }

    public int bytesToIntLittleEndian(byte[] bArr, int i) {
        int i2 = i + 1;
        int i3 = i2 + 1;
        return (bArr[i] & 255) | ((bArr[i2] & 255) << 8) | ((bArr[i3] & 255) << 16) | ((bArr[i3 + 1] & 255) << 24);
    }

    public byte[] concatenateArray(byte[][] bArr) {
        byte[] bArr2 = new byte[bArr.length * bArr[0].length];
        int i = 0;
        for (int i2 = 0; i2 < bArr.length; i2++) {
            System.arraycopy(bArr[i2], 0, bArr2, i, bArr[i2].length);
            i += bArr[i2].length;
        }
        return bArr2;
    }

    public void printArray(String str, byte[][] bArr) {
        System.out.println(str);
        int i = 0;
        for (int i2 = 0; i2 < bArr.length; i2++) {
            for (int i3 = 0; i3 < bArr[0].length; i3++) {
                System.out.println(i + "; " + ((int) bArr[i2][i3]));
                i++;
            }
        }
    }

    public void printArray(String str, byte[] bArr) {
        System.out.println(str);
        int i = 0;
        for (int i2 = 0; i2 < bArr.length; i2++) {
            System.out.println(i + "; " + ((int) bArr[i2]));
            i++;
        }
    }

    public boolean testPowerOfTwo(int i) {
        int i2;
        int i3 = 1;
        while (true) {
            i2 = i3;
            if (i2 >= i) {
                break;
            }
            i3 = i2 << 1;
        }
        return i == i2;
    }

    public int getLog(int i) {
        int i2 = 1;
        int i3 = 2;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        return i2;
    }
}