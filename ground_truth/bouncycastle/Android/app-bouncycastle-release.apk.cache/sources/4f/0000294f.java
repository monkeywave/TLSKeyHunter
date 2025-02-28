package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMEngine;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class BIKEEngine {
    private int L_BYTE;
    private int R2_BYTE;
    private int R_BYTE;
    private final BIKERing bikeRing;

    /* renamed from: hw */
    private int f1204hw;
    private int nbIter;

    /* renamed from: r */
    private int f1205r;

    /* renamed from: t */
    private int f1206t;
    private int tau;

    /* renamed from: w */
    private int f1207w;

    public BIKEEngine(int i, int i2, int i3, int i4, int i5, int i6) {
        this.f1205r = i;
        this.f1207w = i2;
        this.f1206t = i3;
        this.nbIter = i5;
        this.tau = i6;
        this.f1204hw = i2 / 2;
        this.L_BYTE = i4 / 8;
        this.R_BYTE = (i + 7) >>> 3;
        this.R2_BYTE = ((i * 2) + 7) >>> 3;
        this.bikeRing = new BIKERing(i);
    }

    private void BFIter(byte[] bArr, byte[] bArr2, int i, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4, byte[] bArr3, byte[] bArr4, byte[] bArr5) {
        ctrAll(iArr3, bArr, bArr5);
        int i2 = bArr5[0] & UByte.MAX_VALUE;
        byte b = (byte) (((i2 - i) >> 31) + 1);
        bArr2[0] = (byte) (bArr2[0] ^ b);
        bArr3[0] = b;
        bArr4[0] = (byte) (((i2 - (i - this.tau)) >> 31) + 1);
        int i3 = 1;
        while (true) {
            int i4 = this.f1205r;
            if (i3 >= i4) {
                break;
            }
            int i5 = bArr5[i3] & UByte.MAX_VALUE;
            int i6 = i4 - i3;
            byte b2 = (byte) (((i5 - i) >> 31) + 1);
            bArr2[i6] = (byte) (bArr2[i6] ^ b2);
            bArr3[i3] = b2;
            bArr4[i3] = (byte) (((i5 - (i - this.tau)) >> 31) + 1);
            i3++;
        }
        ctrAll(iArr4, bArr, bArr5);
        int i7 = bArr5[0] & UByte.MAX_VALUE;
        int i8 = this.f1205r;
        byte b3 = (byte) (((i7 - i) >> 31) + 1);
        bArr2[i8] = (byte) (bArr2[i8] ^ b3);
        bArr3[i8] = b3;
        bArr4[i8] = (byte) (((i7 - (i - this.tau)) >> 31) + 1);
        int i9 = 1;
        while (true) {
            int i10 = this.f1205r;
            if (i9 >= i10) {
                break;
            }
            int i11 = bArr5[i9] & UByte.MAX_VALUE;
            int i12 = (i10 + i10) - i9;
            byte b4 = (byte) (((i11 - i) >> 31) + 1);
            bArr2[i12] = (byte) (bArr2[i12] ^ b4);
            bArr3[i10 + i9] = b4;
            bArr4[i10 + i9] = (byte) (((i11 - (i - this.tau)) >> 31) + 1);
            i9++;
        }
        for (int i13 = 0; i13 < this.f1205r * 2; i13++) {
            recomputeSyndrome(bArr, i13, iArr, iArr2, bArr3[i13] != 0);
        }
    }

    private void BFIter2(byte[] bArr, byte[] bArr2, int i, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4, byte[] bArr3) {
        int[] iArr5 = new int[this.f1205r * 2];
        ctrAll(iArr3, bArr, bArr3);
        int i2 = (((bArr3[0] & UByte.MAX_VALUE) - i) >> 31) + 1;
        bArr2[0] = (byte) (bArr2[0] ^ ((byte) i2));
        iArr5[0] = i2;
        int i3 = 1;
        while (true) {
            int i4 = this.f1205r;
            if (i3 >= i4) {
                break;
            }
            int i5 = (((bArr3[i3] & UByte.MAX_VALUE) - i) >> 31) + 1;
            int i6 = i4 - i3;
            bArr2[i6] = (byte) (bArr2[i6] ^ ((byte) i5));
            iArr5[i3] = i5;
            i3++;
        }
        ctrAll(iArr4, bArr, bArr3);
        int i7 = (((bArr3[0] & UByte.MAX_VALUE) - i) >> 31) + 1;
        int i8 = this.f1205r;
        bArr2[i8] = (byte) (bArr2[i8] ^ ((byte) i7));
        iArr5[i8] = i7;
        int i9 = 1;
        while (true) {
            int i10 = this.f1205r;
            if (i9 >= i10) {
                break;
            }
            int i11 = (((bArr3[i9] & UByte.MAX_VALUE) - i) >> 31) + 1;
            int i12 = (i10 + i10) - i9;
            bArr2[i12] = (byte) (bArr2[i12] ^ ((byte) i11));
            iArr5[i10 + i9] = i11;
            i9++;
        }
        for (int i13 = 0; i13 < this.f1205r * 2; i13++) {
            recomputeSyndrome(bArr, i13, iArr, iArr2, iArr5[i13] == 1);
        }
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r10v0 */
    /* JADX WARN: Type inference failed for: r10v1, types: [boolean] */
    /* JADX WARN: Type inference failed for: r10v2 */
    /* JADX WARN: Type inference failed for: r4v2 */
    /* JADX WARN: Type inference failed for: r4v3, types: [boolean] */
    /* JADX WARN: Type inference failed for: r4v4 */
    private void BFMaskedIter(byte[] bArr, byte[] bArr2, byte[] bArr3, int i, int[] iArr, int[] iArr2, int[] iArr3, int[] iArr4) {
        int[] iArr5 = new int[this.f1205r * 2];
        int i2 = 0;
        while (true) {
            if (i2 >= this.f1205r) {
                break;
            }
            if (bArr3[i2] == 1) {
                ?? r10 = ctr(iArr3, bArr, i2) < i ? 0 : 1;
                updateNewErrorIndex(bArr2, i2, r10);
                iArr5[i2] = r10;
            }
            i2++;
        }
        int i3 = 0;
        while (true) {
            int i4 = this.f1205r;
            if (i3 >= i4) {
                break;
            }
            if (bArr3[i4 + i3] == 1) {
                ?? r4 = ctr(iArr4, bArr, i3) >= i ? 1 : 0;
                updateNewErrorIndex(bArr2, this.f1205r + i3, r4);
                iArr5[this.f1205r + i3] = r4;
            }
            i3++;
        }
        for (int i5 = 0; i5 < this.f1205r * 2; i5++) {
            recomputeSyndrome(bArr, i5, iArr, iArr2, iArr5[i5] == 1);
        }
    }

    private byte[] BGFDecoder(byte[] bArr, int[] iArr, int[] iArr2) {
        byte[] bArr2 = new byte[this.f1205r * 2];
        int[] columnFromCompactVersion = getColumnFromCompactVersion(iArr);
        int[] columnFromCompactVersion2 = getColumnFromCompactVersion(iArr2);
        int i = this.f1205r;
        byte[] bArr3 = new byte[i * 2];
        byte[] bArr4 = new byte[i];
        byte[] bArr5 = new byte[i * 2];
        BFIter(bArr, bArr2, threshold(BIKEUtils.getHammingWeight(bArr), this.f1205r), iArr, iArr2, columnFromCompactVersion, columnFromCompactVersion2, bArr3, bArr5, bArr4);
        BFMaskedIter(bArr, bArr2, bArr3, ((this.f1204hw + 1) / 2) + 1, iArr, iArr2, columnFromCompactVersion, columnFromCompactVersion2);
        BFMaskedIter(bArr, bArr2, bArr5, ((this.f1204hw + 1) / 2) + 1, iArr, iArr2, columnFromCompactVersion, columnFromCompactVersion2);
        for (int i2 = 1; i2 < this.nbIter; i2++) {
            Arrays.fill(bArr3, (byte) 0);
            BFIter2(bArr, bArr2, threshold(BIKEUtils.getHammingWeight(bArr), this.f1205r), iArr, iArr2, columnFromCompactVersion, columnFromCompactVersion2, bArr4);
        }
        if (BIKEUtils.getHammingWeight(bArr) == 0) {
            return bArr2;
        }
        return null;
    }

    private byte[] computeSyndrome(byte[] bArr, byte[] bArr2) {
        long[] create = this.bikeRing.create();
        long[] create2 = this.bikeRing.create();
        this.bikeRing.decodeBytes(bArr, create);
        this.bikeRing.decodeBytes(bArr2, create2);
        this.bikeRing.multiply(create, create2, create);
        return this.bikeRing.encodeBitsTransposed(create);
    }

    private void convertToCompact(int[] iArr, byte[] bArr) {
        int i;
        int i2 = 0;
        for (int i3 = 0; i3 < this.R_BYTE; i3++) {
            for (int i4 = 0; i4 < 8 && (i = (i3 * 8) + i4) != this.f1205r; i4++) {
                int i5 = (bArr[i3] >> i4) & 1;
                int i6 = -i5;
                iArr[i2] = (i & i6) | ((~i6) & iArr[i2]);
                i2 = (i2 + i5) % this.f1204hw;
            }
        }
    }

    private int ctr(int[] iArr, byte[] bArr, int i) {
        int i2 = this.f1204hw - 4;
        int i3 = 0;
        int i4 = 0;
        while (i3 <= i2) {
            int i5 = this.f1205r;
            int i6 = (iArr[i3] + i) - i5;
            int i7 = (iArr[i3 + 1] + i) - i5;
            int i8 = (iArr[i3 + 2] + i) - i5;
            int i9 = (iArr[i3 + 3] + i) - i5;
            i4 = i4 + (bArr[i6 + ((i6 >> 31) & i5)] & UByte.MAX_VALUE) + (bArr[i7 + ((i7 >> 31) & i5)] & UByte.MAX_VALUE) + (bArr[i8 + ((i8 >> 31) & i5)] & UByte.MAX_VALUE) + (bArr[i9 + (i5 & (i9 >> 31))] & UByte.MAX_VALUE);
            i3 += 4;
        }
        while (i3 < this.f1204hw) {
            int i10 = this.f1205r;
            int i11 = (iArr[i3] + i) - i10;
            i4 += bArr[i11 + (i10 & (i11 >> 31))] & UByte.MAX_VALUE;
            i3++;
        }
        return i4;
    }

    private void ctrAll(int[] iArr, byte[] bArr, byte[] bArr2) {
        int i = iArr[0];
        int i2 = this.f1205r - i;
        System.arraycopy(bArr, i, bArr2, 0, i2);
        System.arraycopy(bArr, 0, bArr2, i2, i);
        for (int i3 = 1; i3 < this.f1204hw; i3++) {
            int i4 = iArr[i3];
            int i5 = this.f1205r - i4;
            int i6 = i5 - 4;
            int i7 = 0;
            while (i7 <= i6) {
                int i8 = i4 + i7;
                bArr2[i7] = (byte) (bArr2[i7] + (bArr[i8] & UByte.MAX_VALUE));
                int i9 = i7 + 1;
                bArr2[i9] = (byte) (bArr2[i9] + (bArr[i8 + 1] & UByte.MAX_VALUE));
                int i10 = i7 + 2;
                bArr2[i10] = (byte) (bArr2[i10] + (bArr[i8 + 2] & UByte.MAX_VALUE));
                int i11 = i7 + 3;
                bArr2[i11] = (byte) (bArr2[i11] + (bArr[i8 + 3] & UByte.MAX_VALUE));
                i7 += 4;
            }
            while (i7 < i5) {
                bArr2[i7] = (byte) (bArr2[i7] + (bArr[i4 + i7] & UByte.MAX_VALUE));
                i7++;
            }
            int i12 = this.f1205r - 4;
            int i13 = i5;
            while (i13 <= i12) {
                bArr2[i13] = (byte) (bArr2[i13] + (bArr[i13 - i5] & UByte.MAX_VALUE));
                int i14 = i13 + 1;
                bArr2[i14] = (byte) (bArr2[i14] + (bArr[i14 - i5] & UByte.MAX_VALUE));
                int i15 = i13 + 2;
                bArr2[i15] = (byte) (bArr2[i15] + (bArr[i15 - i5] & UByte.MAX_VALUE));
                int i16 = i13 + 3;
                bArr2[i16] = (byte) (bArr2[i16] + (bArr[i16 - i5] & UByte.MAX_VALUE));
                i13 += 4;
            }
            while (i13 < this.f1205r) {
                bArr2[i13] = (byte) (bArr2[i13] + (bArr[i13 - i5] & UByte.MAX_VALUE));
                i13++;
            }
        }
    }

    private byte[] functionH(byte[] bArr) {
        byte[] bArr2 = new byte[this.R_BYTE * 2];
        SHAKEDigest sHAKEDigest = new SHAKEDigest(256);
        sHAKEDigest.update(bArr, 0, bArr.length);
        BIKEUtils.generateRandomByteArray(bArr2, this.f1205r * 2, this.f1206t, sHAKEDigest);
        return bArr2;
    }

    private void functionK(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        byte[] bArr5 = new byte[48];
        SHA3Digest sHA3Digest = new SHA3Digest((int) MLKEMEngine.KyberPolyBytes);
        sHA3Digest.update(bArr, 0, bArr.length);
        sHA3Digest.update(bArr2, 0, bArr2.length);
        sHA3Digest.update(bArr3, 0, bArr3.length);
        sHA3Digest.doFinal(bArr5, 0);
        System.arraycopy(bArr5, 0, bArr4, 0, this.L_BYTE);
    }

    private void functionL(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        byte[] bArr4 = new byte[48];
        SHA3Digest sHA3Digest = new SHA3Digest((int) MLKEMEngine.KyberPolyBytes);
        sHA3Digest.update(bArr, 0, bArr.length);
        sHA3Digest.update(bArr2, 0, bArr2.length);
        sHA3Digest.doFinal(bArr4, 0);
        System.arraycopy(bArr4, 0, bArr3, 0, this.L_BYTE);
    }

    private int[] getColumnFromCompactVersion(int[] iArr) {
        int[] iArr2 = new int[this.f1204hw];
        int i = 0;
        if (iArr[0] != 0) {
            while (true) {
                int i2 = this.f1204hw;
                if (i >= i2) {
                    break;
                }
                iArr2[i] = this.f1205r - iArr[(i2 - 1) - i];
                i++;
            }
        } else {
            iArr2[0] = 0;
            int i3 = 1;
            while (true) {
                int i4 = this.f1204hw;
                if (i3 >= i4) {
                    break;
                }
                iArr2[i3] = this.f1205r - iArr[i4 - i3];
                i3++;
            }
        }
        return iArr2;
    }

    private void recomputeSyndrome(byte[] bArr, int i, int[] iArr, int[] iArr2, boolean z) {
        int i2 = 0;
        if (i < this.f1205r) {
            while (i2 < this.f1204hw) {
                int i3 = iArr[i2];
                if (i3 <= i) {
                    int i4 = i - i3;
                    bArr[i4] = (byte) (bArr[i4] ^ (z ? 1 : 0));
                } else {
                    int i5 = (this.f1205r + i) - i3;
                    bArr[i5] = (byte) (bArr[i5] ^ (z ? 1 : 0));
                }
                i2++;
            }
            return;
        }
        while (i2 < this.f1204hw) {
            int i6 = iArr2[i2];
            int i7 = this.f1205r;
            if (i6 <= i - i7) {
                int i8 = (i - i7) - i6;
                bArr[i8] = (byte) (bArr[i8] ^ (z ? 1 : 0));
            } else {
                int i9 = (i7 - i6) + (i - i7);
                bArr[i9] = (byte) (bArr[i9] ^ (z ? 1 : 0));
            }
            i2++;
        }
    }

    private void splitEBytes(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int i = this.f1205r & 7;
        int i2 = 0;
        System.arraycopy(bArr, 0, bArr2, 0, this.R_BYTE - 1);
        int i3 = this.R_BYTE;
        byte b = bArr[i3 - 1];
        byte b2 = (byte) ((-1) << i);
        bArr2[i3 - 1] = (byte) ((~b2) & b);
        byte b3 = (byte) (b & b2);
        while (true) {
            int i4 = this.R_BYTE;
            if (i2 >= i4) {
                return;
            }
            byte b4 = bArr[i4 + i2];
            bArr3[i2] = (byte) (((b3 & UByte.MAX_VALUE) >>> i) | (b4 << (8 - i)));
            i2++;
            b3 = b4;
        }
    }

    private int threshold(int i, int i2) {
        if (i2 != 12323) {
            if (i2 != 24659) {
                if (i2 == 40973) {
                    return thresholdFromParameters(i, 0.00402312d, 17.8785d, 69);
                }
                throw new IllegalArgumentException();
            }
            return thresholdFromParameters(i, 0.005265d, 15.2588d, 52);
        }
        return thresholdFromParameters(i, 0.0069722d, 13.53d, 36);
    }

    private static int thresholdFromParameters(int i, double d, double d2, int i2) {
        return Math.max(i2, (int) Math.floor((d * i) + d2));
    }

    private void updateNewErrorIndex(byte[] bArr, int i, boolean z) {
        int i2;
        if (i != 0 && i != (i2 = this.f1205r)) {
            i = i > i2 ? ((i2 * 2) - i) + i2 : i2 - i;
        }
        bArr[i] = (byte) ((z ? 1 : 0) ^ bArr[i]);
    }

    public void decaps(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6) {
        int i = this.f1204hw;
        int[] iArr = new int[i];
        int[] iArr2 = new int[i];
        convertToCompact(iArr, bArr2);
        convertToCompact(iArr2, bArr3);
        byte[] BGFDecoder = BGFDecoder(computeSyndrome(bArr5, bArr2), iArr, iArr2);
        byte[] bArr7 = new byte[this.R_BYTE * 2];
        BIKEUtils.fromBitArrayToByteArray(bArr7, BGFDecoder, 0, this.f1205r * 2);
        int i2 = this.R_BYTE;
        byte[] bArr8 = new byte[i2];
        byte[] bArr9 = new byte[i2];
        splitEBytes(bArr7, bArr8, bArr9);
        byte[] bArr10 = new byte[this.L_BYTE];
        functionL(bArr8, bArr9, bArr10);
        Bytes.xorTo(this.L_BYTE, bArr6, bArr10);
        byte[] functionH = functionH(bArr10);
        int i3 = this.R2_BYTE;
        if (Arrays.areEqual(bArr7, 0, i3, functionH, 0, i3)) {
            functionK(bArr10, bArr5, bArr6, bArr);
        } else {
            functionK(bArr4, bArr5, bArr6, bArr);
        }
    }

    public void encaps(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, SecureRandom secureRandom) {
        byte[] bArr5 = new byte[this.L_BYTE];
        secureRandom.nextBytes(bArr5);
        byte[] functionH = functionH(bArr5);
        int i = this.R_BYTE;
        byte[] bArr6 = new byte[i];
        byte[] bArr7 = new byte[i];
        splitEBytes(functionH, bArr6, bArr7);
        long[] create = this.bikeRing.create();
        long[] create2 = this.bikeRing.create();
        this.bikeRing.decodeBytes(bArr6, create);
        this.bikeRing.decodeBytes(bArr7, create2);
        long[] create3 = this.bikeRing.create();
        this.bikeRing.decodeBytes(bArr4, create3);
        this.bikeRing.multiply(create3, create2, create3);
        this.bikeRing.add(create3, create, create3);
        this.bikeRing.encodeBytes(create3, bArr);
        functionL(bArr6, bArr7, bArr2);
        Bytes.xorTo(this.L_BYTE, bArr5, bArr2);
        functionK(bArr5, bArr, bArr2, bArr3);
    }

    public void genKeyPair(byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, SecureRandom secureRandom) {
        byte[] bArr5 = new byte[64];
        secureRandom.nextBytes(bArr5);
        SHAKEDigest sHAKEDigest = new SHAKEDigest(256);
        sHAKEDigest.update(bArr5, 0, this.L_BYTE);
        BIKEUtils.generateRandomByteArray(bArr, this.f1205r, this.f1204hw, sHAKEDigest);
        BIKEUtils.generateRandomByteArray(bArr2, this.f1205r, this.f1204hw, sHAKEDigest);
        long[] create = this.bikeRing.create();
        long[] create2 = this.bikeRing.create();
        this.bikeRing.decodeBytes(bArr, create);
        this.bikeRing.decodeBytes(bArr2, create2);
        long[] create3 = this.bikeRing.create();
        this.bikeRing.inv(create, create3);
        this.bikeRing.multiply(create3, create2, create3);
        this.bikeRing.encodeBytes(create3, bArr4);
        System.arraycopy(bArr5, this.L_BYTE, bArr3, 0, bArr3.length);
    }

    public int getSessionKeySize() {
        return this.L_BYTE;
    }
}