package org.bouncycastle.pqc.crypto.sphincs;

import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincs/Permute.class */
class Permute {
    private static final int CHACHA_ROUNDS = 12;

    protected static int rotl(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    public static void permute(int i, int[] iArr) {
        if (iArr.length != 16) {
            throw new IllegalArgumentException();
        }
        if (i % 2 != 0) {
            throw new IllegalArgumentException("Number of rounds must be even");
        }
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = iArr[7];
        int i10 = iArr[8];
        int i11 = iArr[9];
        int i12 = iArr[10];
        int i13 = iArr[11];
        int i14 = iArr[12];
        int i15 = iArr[13];
        int i16 = iArr[14];
        int i17 = iArr[15];
        for (int i18 = i; i18 > 0; i18 -= 2) {
            int i19 = i2 + i6;
            int rotl = rotl(i14 ^ i19, 16);
            int i20 = i10 + rotl;
            int rotl2 = rotl(i6 ^ i20, 12);
            int i21 = i19 + rotl2;
            int rotl3 = rotl(rotl ^ i21, 8);
            int i22 = i20 + rotl3;
            int rotl4 = rotl(rotl2 ^ i22, 7);
            int i23 = i3 + i7;
            int rotl5 = rotl(i15 ^ i23, 16);
            int i24 = i11 + rotl5;
            int rotl6 = rotl(i7 ^ i24, 12);
            int i25 = i23 + rotl6;
            int rotl7 = rotl(rotl5 ^ i25, 8);
            int i26 = i24 + rotl7;
            int rotl8 = rotl(rotl6 ^ i26, 7);
            int i27 = i4 + i8;
            int rotl9 = rotl(i16 ^ i27, 16);
            int i28 = i12 + rotl9;
            int rotl10 = rotl(i8 ^ i28, 12);
            int i29 = i27 + rotl10;
            int rotl11 = rotl(rotl9 ^ i29, 8);
            int i30 = i28 + rotl11;
            int rotl12 = rotl(rotl10 ^ i30, 7);
            int i31 = i5 + i9;
            int rotl13 = rotl(i17 ^ i31, 16);
            int i32 = i13 + rotl13;
            int rotl14 = rotl(i9 ^ i32, 12);
            int i33 = i31 + rotl14;
            int rotl15 = rotl(rotl13 ^ i33, 8);
            int i34 = i32 + rotl15;
            int rotl16 = rotl(rotl14 ^ i34, 7);
            int i35 = i21 + rotl8;
            int rotl17 = rotl(rotl15 ^ i35, 16);
            int i36 = i30 + rotl17;
            int rotl18 = rotl(rotl8 ^ i36, 12);
            i2 = i35 + rotl18;
            i17 = rotl(rotl17 ^ i2, 8);
            i12 = i36 + i17;
            i7 = rotl(rotl18 ^ i12, 7);
            int i37 = i25 + rotl12;
            int rotl19 = rotl(rotl3 ^ i37, 16);
            int i38 = i34 + rotl19;
            int rotl20 = rotl(rotl12 ^ i38, 12);
            i3 = i37 + rotl20;
            i14 = rotl(rotl19 ^ i3, 8);
            i13 = i38 + i14;
            i8 = rotl(rotl20 ^ i13, 7);
            int i39 = i29 + rotl16;
            int rotl21 = rotl(rotl7 ^ i39, 16);
            int i40 = i22 + rotl21;
            int rotl22 = rotl(rotl16 ^ i40, 12);
            i4 = i39 + rotl22;
            i15 = rotl(rotl21 ^ i4, 8);
            i10 = i40 + i15;
            i9 = rotl(rotl22 ^ i10, 7);
            int i41 = i33 + rotl4;
            int rotl23 = rotl(rotl11 ^ i41, 16);
            int i42 = i26 + rotl23;
            int rotl24 = rotl(rotl4 ^ i42, 12);
            i5 = i41 + rotl24;
            i16 = rotl(rotl23 ^ i5, 8);
            i11 = i42 + i16;
            i6 = rotl(rotl24 ^ i11, 7);
        }
        iArr[0] = i2;
        iArr[1] = i3;
        iArr[2] = i4;
        iArr[3] = i5;
        iArr[4] = i6;
        iArr[5] = i7;
        iArr[6] = i8;
        iArr[7] = i9;
        iArr[8] = i10;
        iArr[9] = i11;
        iArr[10] = i12;
        iArr[11] = i13;
        iArr[12] = i14;
        iArr[13] = i15;
        iArr[14] = i16;
        iArr[15] = i17;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void chacha_permute(byte[] bArr, byte[] bArr2) {
        int[] iArr = new int[16];
        for (int i = 0; i < 16; i++) {
            iArr[i] = Pack.littleEndianToInt(bArr2, 4 * i);
        }
        permute(12, iArr);
        for (int i2 = 0; i2 < 16; i2++) {
            Pack.intToLittleEndian(iArr[i2], bArr, 4 * i2);
        }
    }
}