package org.bouncycastle.pqc.crypto.newhope;

import kotlin.UByte;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
class Poly {
    Poly() {
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void add(short[] sArr, short[] sArr2, short[] sArr3) {
        for (int i = 0; i < 1024; i++) {
            sArr3[i] = Reduce.barrett((short) (sArr[i] + sArr2[i]));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void fromBytes(short[] sArr, byte[] bArr) {
        for (int i = 0; i < 256; i++) {
            int i2 = i * 7;
            int i3 = bArr[i2] & UByte.MAX_VALUE;
            byte b = bArr[i2 + 1];
            int i4 = b & UByte.MAX_VALUE;
            int i5 = bArr[i2 + 2] & UByte.MAX_VALUE;
            byte b2 = bArr[i2 + 3];
            int i6 = b2 & UByte.MAX_VALUE;
            int i7 = bArr[i2 + 4] & UByte.MAX_VALUE;
            byte b3 = bArr[i2 + 5];
            int i8 = b3 & UByte.MAX_VALUE;
            int i9 = bArr[i2 + 6] & UByte.MAX_VALUE;
            int i10 = i * 4;
            sArr[i10] = (short) (i3 | ((b & 63) << 8));
            sArr[i10 + 1] = (short) ((i4 >>> 6) | (i5 << 2) | ((b2 & 15) << 10));
            sArr[i10 + 2] = (short) ((i6 >>> 4) | (i7 << 4) | ((b3 & 3) << 12));
            sArr[i10 + 3] = (short) ((i9 << 6) | (i8 >>> 2));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void fromNTT(short[] sArr) {
        NTT.bitReverse(sArr);
        NTT.core(sArr, Precomp.OMEGAS_INV_MONTGOMERY);
        NTT.mulCoefficients(sArr, Precomp.PSIS_INV_MONTGOMERY);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void getNoise(short[] sArr, byte[] bArr, byte b) {
        byte[] bArr2 = new byte[8];
        bArr2[0] = b;
        byte[] bArr3 = new byte[4096];
        ChaCha20.process(bArr, bArr2, bArr3, 0, 4096);
        for (int i = 0; i < 1024; i++) {
            int bigEndianToInt = Pack.bigEndianToInt(bArr3, i * 4);
            int i2 = 0;
            for (int i3 = 0; i3 < 8; i3++) {
                i2 += (bigEndianToInt >> i3) & 16843009;
            }
            sArr[i] = (short) (((((i2 >>> 24) + i2) & 255) + 12289) - (((i2 >>> 16) + (i2 >>> 8)) & 255));
        }
    }

    private static short normalize(short s) {
        short barrett = Reduce.barrett(s);
        int i = barrett - 12289;
        return (short) (((barrett ^ i) & (i >> 31)) ^ i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void pointWise(short[] sArr, short[] sArr2, short[] sArr3) {
        for (int i = 0; i < 1024; i++) {
            sArr3[i] = Reduce.montgomery((sArr[i] & 65535) * (65535 & Reduce.montgomery((sArr2[i] & 65535) * 3186)));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void toBytes(byte[] bArr, short[] sArr) {
        for (int i = 0; i < 256; i++) {
            int i2 = i * 4;
            short normalize = normalize(sArr[i2]);
            short normalize2 = normalize(sArr[i2 + 1]);
            short normalize3 = normalize(sArr[i2 + 2]);
            short normalize4 = normalize(sArr[i2 + 3]);
            int i3 = i * 7;
            bArr[i3] = (byte) normalize;
            bArr[i3 + 1] = (byte) ((normalize >> 8) | (normalize2 << 6));
            bArr[i3 + 2] = (byte) (normalize2 >> 2);
            bArr[i3 + 3] = (byte) ((normalize2 >> 10) | (normalize3 << 4));
            bArr[i3 + 4] = (byte) (normalize3 >> 4);
            bArr[i3 + 5] = (byte) ((normalize3 >> 12) | (normalize4 << 2));
            bArr[i3 + 6] = (byte) (normalize4 >> 6);
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void toNTT(short[] sArr) {
        NTT.mulCoefficients(sArr, Precomp.PSIS_BITREV_MONTGOMERY);
        NTT.core(sArr, Precomp.OMEGAS_MONTGOMERY);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void uniform(short[] sArr, byte[] bArr) {
        SHAKEDigest sHAKEDigest = new SHAKEDigest(128);
        sHAKEDigest.update(bArr, 0, bArr.length);
        int i = 0;
        while (true) {
            byte[] bArr2 = new byte[256];
            sHAKEDigest.doOutput(bArr2, 0, 256);
            for (int i2 = 0; i2 < 256; i2 += 2) {
                int i3 = (bArr2[i2] & UByte.MAX_VALUE) | ((bArr2[i2 + 1] & UByte.MAX_VALUE) << 8);
                if (i3 < 61445) {
                    int i4 = i + 1;
                    sArr[i] = (short) i3;
                    if (i4 == 1024) {
                        return;
                    }
                    i = i4;
                }
            }
        }
    }
}