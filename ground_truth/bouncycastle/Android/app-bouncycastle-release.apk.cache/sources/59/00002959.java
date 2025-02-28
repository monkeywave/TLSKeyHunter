package org.bouncycastle.pqc.crypto.bike;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
class BIKEUtils {
    BIKEUtils() {
    }

    protected static int CHECK_BIT(byte[] bArr, int i) {
        return (bArr[i / 8] >>> (i % 8)) & 1;
    }

    protected static void SET_BIT(byte[] bArr, int i) {
        int i2 = i / 8;
        bArr[i2] = (byte) (bArr[i2] | (1 << (i % 8)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void fromBitArrayToByteArray(byte[] bArr, byte[] bArr2, int i, int i2) {
        long j = i2;
        int i3 = 0;
        int i4 = 0;
        while (i3 < j) {
            int i5 = i3 + 8;
            if (i5 >= i2) {
                int i6 = i + i3;
                int i7 = bArr2[i6];
                for (int i8 = (i2 - i3) - 1; i8 >= 1; i8--) {
                    i7 |= bArr2[i6 + i8] << i8;
                }
                bArr[i4] = (byte) i7;
            } else {
                int i9 = i3 + i;
                int i10 = bArr2[i9];
                for (int i11 = 7; i11 >= 1; i11--) {
                    i10 |= bArr2[i9 + i11] << i11;
                }
                bArr[i4] = (byte) i10;
            }
            i4++;
            i3 = i5;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void generateRandomByteArray(byte[] bArr, int i, int i2, Xof xof) {
        byte[] bArr2 = new byte[4];
        for (int i3 = i2 - 1; i3 >= 0; i3--) {
            xof.doOutput(bArr2, 0, 4);
            int littleEndianToInt = ((int) (((Pack.littleEndianToInt(bArr2, 0) & BodyPartID.bodyIdMax) * (i - i3)) >> 32)) + i3;
            if (CHECK_BIT(bArr, littleEndianToInt) != 0) {
                littleEndianToInt = i3;
            }
            SET_BIT(bArr, littleEndianToInt);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getHammingWeight(byte[] bArr) {
        int i = 0;
        for (byte b : bArr) {
            i += b;
        }
        return i;
    }
}