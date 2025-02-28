package org.bouncycastle.crypto.engines;

import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/AESLightEngine.class */
public class AESLightEngine implements BlockCipher {

    /* renamed from: S */
    private static final byte[] f294S = {99, 124, 119, 123, -14, 107, 111, -59, 48, 1, 103, 43, -2, -41, -85, 118, -54, -126, -55, 125, -6, 89, 71, -16, -83, -44, -94, -81, -100, -92, 114, -64, -73, -3, -109, 38, 54, 63, -9, -52, 52, -91, -27, -15, 113, -40, 49, 21, 4, -57, 35, -61, 24, -106, 5, -102, 7, 18, Byte.MIN_VALUE, -30, -21, 39, -78, 117, 9, -125, 44, 26, 27, 110, 90, -96, 82, 59, -42, -77, 41, -29, 47, -124, 83, -47, 0, -19, 32, -4, -79, 91, 106, -53, -66, 57, 74, 76, 88, -49, -48, -17, -86, -5, 67, 77, 51, -123, 69, -7, 2, Byte.MAX_VALUE, 80, 60, -97, -88, 81, -93, 64, -113, -110, -99, 56, -11, -68, -74, -38, 33, 16, -1, -13, -46, -51, 12, 19, -20, 95, -105, 68, 23, -60, -89, 126, 61, 100, 93, 25, 115, 96, -127, 79, -36, 34, 42, -112, -120, 70, -18, -72, 20, -34, 94, 11, -37, -32, 50, 58, 10, 73, 6, 36, 92, -62, -45, -84, 98, -111, -107, -28, 121, -25, -56, 55, 109, -115, -43, 78, -87, 108, 86, -12, -22, 101, 122, -82, 8, -70, 120, 37, 46, 28, -90, -76, -58, -24, -35, 116, 31, 75, -67, -117, -118, 112, 62, -75, 102, 72, 3, -10, 14, 97, 53, 87, -71, -122, -63, 29, -98, -31, -8, -104, 17, 105, -39, -114, -108, -101, 30, -121, -23, -50, 85, 40, -33, -116, -95, -119, 13, -65, -26, 66, 104, 65, -103, 45, 15, -80, 84, -69, 22};

    /* renamed from: Si */
    private static final byte[] f295Si = {82, 9, 106, -43, 48, 54, -91, 56, -65, 64, -93, -98, -127, -13, -41, -5, 124, -29, 57, -126, -101, 47, -1, -121, 52, -114, 67, 68, -60, -34, -23, -53, 84, 123, -108, 50, -90, -62, 35, 61, -18, 76, -107, 11, 66, -6, -61, 78, 8, 46, -95, 102, 40, -39, 36, -78, 118, 91, -94, 73, 109, -117, -47, 37, 114, -8, -10, 100, -122, 104, -104, 22, -44, -92, 92, -52, 93, 101, -74, -110, 108, 112, 72, 80, -3, -19, -71, -38, 94, 21, 70, 87, -89, -115, -99, -124, -112, -40, -85, 0, -116, -68, -45, 10, -9, -28, 88, 5, -72, -77, 69, 6, -48, 44, 30, -113, -54, 63, 15, 2, -63, -81, -67, 3, 1, 19, -118, 107, 58, -111, 17, 65, 79, 103, -36, -22, -105, -14, -49, -50, -16, -76, -26, 115, -106, -84, 116, 34, -25, -83, 53, -123, -30, -7, 55, -24, 28, 117, -33, 110, 71, -15, 26, 113, 29, 41, -59, -119, 111, -73, 98, 14, -86, 24, -66, 27, -4, 86, 62, 75, -58, -46, 121, 32, -102, -37, -64, -2, 120, -51, 90, -12, 31, -35, -88, 51, -120, 7, -57, 49, -79, 18, 16, 89, 39, Byte.MIN_VALUE, -20, 95, 96, 81, Byte.MAX_VALUE, -87, 25, -75, 74, 13, 45, -27, 122, -97, -109, -55, -100, -17, -96, -32, 59, 77, -82, 42, -11, -80, -56, -21, -69, 60, -125, 83, -103, 97, 23, 43, 4, 126, -70, 119, -42, 38, -31, 105, 20, 99, 85, 33, 12, 125};
    private static final int[] rcon = {1, 2, 4, 8, 16, 32, 64, 128, 27, 54, Opcode.IDIV, 216, Opcode.LOOKUPSWITCH, 77, Opcode.IFNE, 47, 94, 188, 99, Opcode.IFNULL, Opcode.DCMPL, 53, Opcode.FMUL, 212, Opcode.PUTSTATIC, Opcode.LUSHR, 250, 239, Opcode.MULTIANEWARRAY, Opcode.I2B};

    /* renamed from: m1 */
    private static final int f296m1 = -2139062144;

    /* renamed from: m2 */
    private static final int f297m2 = 2139062143;

    /* renamed from: m3 */
    private static final int f298m3 = 27;

    /* renamed from: m4 */
    private static final int f299m4 = -1061109568;

    /* renamed from: m5 */
    private static final int f300m5 = 1061109567;
    private int ROUNDS;
    private int[][] WorkingKey = null;
    private boolean forEncryption;
    private static final int BLOCK_SIZE = 16;

    private static int shift(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    private static int FFmulX(int i) {
        return ((i & f297m2) << 1) ^ (((i & f296m1) >>> 7) * 27);
    }

    private static int FFmulX2(int i) {
        int i2 = (i & f300m5) << 2;
        int i3 = i & f299m4;
        int i4 = i3 ^ (i3 >>> 1);
        return (i2 ^ (i4 >>> 2)) ^ (i4 >>> 5);
    }

    private static int mcol(int i) {
        int shift = shift(i, 8);
        int i2 = i ^ shift;
        return (shift(i2, 16) ^ shift) ^ FFmulX(i2);
    }

    private static int inv_mcol(int i) {
        int shift = i ^ shift(i, 8);
        int FFmulX = i ^ FFmulX(shift);
        int FFmulX2 = shift ^ FFmulX2(FFmulX);
        return FFmulX ^ (FFmulX2 ^ shift(FFmulX2, 16));
    }

    private static int subWord(int i) {
        return (f294S[i & GF2Field.MASK] & 255) | ((f294S[(i >> 8) & GF2Field.MASK] & 255) << 8) | ((f294S[(i >> 16) & GF2Field.MASK] & 255) << 16) | (f294S[(i >> 24) & GF2Field.MASK] << 24);
    }

    private int[][] generateWorkingKey(byte[] bArr, boolean z) {
        int length = bArr.length;
        if (length < 16 || length > 32 || (length & 7) != 0) {
            throw new IllegalArgumentException("Key length not 128/192/256 bits.");
        }
        int i = length >>> 2;
        this.ROUNDS = i + 6;
        int[][] iArr = new int[this.ROUNDS + 1][4];
        switch (i) {
            case 4:
                int littleEndianToInt = Pack.littleEndianToInt(bArr, 0);
                iArr[0][0] = littleEndianToInt;
                int littleEndianToInt2 = Pack.littleEndianToInt(bArr, 4);
                iArr[0][1] = littleEndianToInt2;
                int littleEndianToInt3 = Pack.littleEndianToInt(bArr, 8);
                iArr[0][2] = littleEndianToInt3;
                int littleEndianToInt4 = Pack.littleEndianToInt(bArr, 12);
                iArr[0][3] = littleEndianToInt4;
                for (int i2 = 1; i2 <= 10; i2++) {
                    littleEndianToInt ^= subWord(shift(littleEndianToInt4, 8)) ^ rcon[i2 - 1];
                    iArr[i2][0] = littleEndianToInt;
                    littleEndianToInt2 ^= littleEndianToInt;
                    iArr[i2][1] = littleEndianToInt2;
                    littleEndianToInt3 ^= littleEndianToInt2;
                    iArr[i2][2] = littleEndianToInt3;
                    littleEndianToInt4 ^= littleEndianToInt3;
                    iArr[i2][3] = littleEndianToInt4;
                }
                break;
            case 5:
            case 7:
            default:
                throw new IllegalStateException("Should never get here");
            case 6:
                int littleEndianToInt5 = Pack.littleEndianToInt(bArr, 0);
                iArr[0][0] = littleEndianToInt5;
                int littleEndianToInt6 = Pack.littleEndianToInt(bArr, 4);
                iArr[0][1] = littleEndianToInt6;
                int littleEndianToInt7 = Pack.littleEndianToInt(bArr, 8);
                iArr[0][2] = littleEndianToInt7;
                int littleEndianToInt8 = Pack.littleEndianToInt(bArr, 12);
                iArr[0][3] = littleEndianToInt8;
                int littleEndianToInt9 = Pack.littleEndianToInt(bArr, 16);
                int littleEndianToInt10 = Pack.littleEndianToInt(bArr, 20);
                int i3 = 1;
                int i4 = 1;
                while (true) {
                    iArr[i3][0] = littleEndianToInt9;
                    iArr[i3][1] = littleEndianToInt10;
                    int i5 = i4 << 1;
                    int subWord = littleEndianToInt5 ^ (subWord(shift(littleEndianToInt10, 8)) ^ i4);
                    iArr[i3][2] = subWord;
                    int i6 = littleEndianToInt6 ^ subWord;
                    iArr[i3][3] = i6;
                    int i7 = littleEndianToInt7 ^ i6;
                    iArr[i3 + 1][0] = i7;
                    int i8 = littleEndianToInt8 ^ i7;
                    iArr[i3 + 1][1] = i8;
                    int i9 = littleEndianToInt9 ^ i8;
                    iArr[i3 + 1][2] = i9;
                    int i10 = littleEndianToInt10 ^ i9;
                    iArr[i3 + 1][3] = i10;
                    i4 = i5 << 1;
                    littleEndianToInt5 = subWord ^ (subWord(shift(i10, 8)) ^ i5);
                    iArr[i3 + 2][0] = littleEndianToInt5;
                    littleEndianToInt6 = i6 ^ littleEndianToInt5;
                    iArr[i3 + 2][1] = littleEndianToInt6;
                    littleEndianToInt7 = i7 ^ littleEndianToInt6;
                    iArr[i3 + 2][2] = littleEndianToInt7;
                    littleEndianToInt8 = i8 ^ littleEndianToInt7;
                    iArr[i3 + 2][3] = littleEndianToInt8;
                    i3 += 3;
                    if (i3 >= 13) {
                        break;
                    } else {
                        littleEndianToInt9 = i9 ^ littleEndianToInt8;
                        littleEndianToInt10 = i10 ^ littleEndianToInt9;
                    }
                }
            case 8:
                int littleEndianToInt11 = Pack.littleEndianToInt(bArr, 0);
                iArr[0][0] = littleEndianToInt11;
                int littleEndianToInt12 = Pack.littleEndianToInt(bArr, 4);
                iArr[0][1] = littleEndianToInt12;
                int littleEndianToInt13 = Pack.littleEndianToInt(bArr, 8);
                iArr[0][2] = littleEndianToInt13;
                int littleEndianToInt14 = Pack.littleEndianToInt(bArr, 12);
                iArr[0][3] = littleEndianToInt14;
                int littleEndianToInt15 = Pack.littleEndianToInt(bArr, 16);
                iArr[1][0] = littleEndianToInt15;
                int littleEndianToInt16 = Pack.littleEndianToInt(bArr, 20);
                iArr[1][1] = littleEndianToInt16;
                int littleEndianToInt17 = Pack.littleEndianToInt(bArr, 24);
                iArr[1][2] = littleEndianToInt17;
                int littleEndianToInt18 = Pack.littleEndianToInt(bArr, 28);
                iArr[1][3] = littleEndianToInt18;
                int i11 = 2;
                int i12 = 1;
                while (true) {
                    int subWord2 = subWord(shift(littleEndianToInt18, 8)) ^ i12;
                    i12 <<= 1;
                    littleEndianToInt11 ^= subWord2;
                    iArr[i11][0] = littleEndianToInt11;
                    littleEndianToInt12 ^= littleEndianToInt11;
                    iArr[i11][1] = littleEndianToInt12;
                    littleEndianToInt13 ^= littleEndianToInt12;
                    iArr[i11][2] = littleEndianToInt13;
                    littleEndianToInt14 ^= littleEndianToInt13;
                    iArr[i11][3] = littleEndianToInt14;
                    int i13 = i11 + 1;
                    if (i13 >= 15) {
                        break;
                    } else {
                        littleEndianToInt15 ^= subWord(littleEndianToInt14);
                        iArr[i13][0] = littleEndianToInt15;
                        littleEndianToInt16 ^= littleEndianToInt15;
                        iArr[i13][1] = littleEndianToInt16;
                        littleEndianToInt17 ^= littleEndianToInt16;
                        iArr[i13][2] = littleEndianToInt17;
                        littleEndianToInt18 ^= littleEndianToInt17;
                        iArr[i13][3] = littleEndianToInt18;
                        i11 = i13 + 1;
                    }
                }
        }
        if (!z) {
            for (int i14 = 1; i14 < this.ROUNDS; i14++) {
                for (int i15 = 0; i15 < 4; i15++) {
                    iArr[i14][i15] = inv_mcol(iArr[i14][i15]);
                }
            }
        }
        return iArr;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to AES init - " + cipherParameters.getClass().getName());
        }
        this.WorkingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey(), z);
        this.forEncryption = z;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "AES";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.WorkingKey == null) {
            throw new IllegalStateException("AES engine not initialised");
        }
        if (i > bArr.length - 16) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 > bArr2.length - 16) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.forEncryption) {
            encryptBlock(bArr, i, bArr2, i2, this.WorkingKey);
            return 16;
        }
        decryptBlock(bArr, i, bArr2, i2, this.WorkingKey);
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    private void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2, int[][] iArr) {
        int littleEndianToInt = Pack.littleEndianToInt(bArr, i + 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, i + 8);
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, i + 12);
        int i3 = littleEndianToInt ^ iArr[0][0];
        int i4 = littleEndianToInt2 ^ iArr[0][1];
        int i5 = littleEndianToInt3 ^ iArr[0][2];
        int i6 = 1;
        int i7 = littleEndianToInt4;
        int i8 = iArr[0][3];
        while (true) {
            int i9 = i7 ^ i8;
            if (i6 >= this.ROUNDS - 1) {
                int mcol = mcol((((f294S[i3 & GF2Field.MASK] & 255) ^ ((f294S[(i4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i9 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][0];
                int mcol2 = mcol((((f294S[i4 & GF2Field.MASK] & 255) ^ ((f294S[(i5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i9 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][1];
                int mcol3 = mcol((((f294S[i5 & GF2Field.MASK] & 255) ^ ((f294S[(i9 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][2];
                int i10 = i6;
                int i11 = i6 + 1;
                int mcol4 = mcol((((f294S[i9 & GF2Field.MASK] & 255) ^ ((f294S[(i3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i5 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i10][3];
                int i12 = ((((f294S[mcol & GF2Field.MASK] & 255) ^ ((f294S[(mcol2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i11][0];
                int i13 = ((((f294S[mcol2 & GF2Field.MASK] & 255) ^ ((f294S[(mcol3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol >> 24) & GF2Field.MASK] << 24)) ^ iArr[i11][1];
                int i14 = ((((f294S[mcol3 & GF2Field.MASK] & 255) ^ ((f294S[(mcol4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol2 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i11][2];
                Pack.intToLittleEndian(i12, bArr2, i2 + 0);
                Pack.intToLittleEndian(i13, bArr2, i2 + 4);
                Pack.intToLittleEndian(i14, bArr2, i2 + 8);
                Pack.intToLittleEndian(((((f294S[mcol4 & GF2Field.MASK] & 255) ^ ((f294S[(mcol >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i11][3], bArr2, i2 + 12);
                return;
            }
            int mcol5 = mcol((((f294S[i3 & GF2Field.MASK] & 255) ^ ((f294S[(i4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i9 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][0];
            int mcol6 = mcol((((f294S[i4 & GF2Field.MASK] & 255) ^ ((f294S[(i5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i9 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][1];
            int mcol7 = mcol((((f294S[i5 & GF2Field.MASK] & 255) ^ ((f294S[(i9 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][2];
            int i15 = i6;
            int i16 = i6 + 1;
            int mcol8 = mcol((((f294S[i9 & GF2Field.MASK] & 255) ^ ((f294S[(i3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(i4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(i5 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i15][3];
            i3 = mcol((((f294S[mcol5 & GF2Field.MASK] & 255) ^ ((f294S[(mcol6 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol7 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol8 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i16][0];
            i4 = mcol((((f294S[mcol6 & GF2Field.MASK] & 255) ^ ((f294S[(mcol7 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol8 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol5 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i16][1];
            i5 = mcol((((f294S[mcol7 & GF2Field.MASK] & 255) ^ ((f294S[(mcol8 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol6 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i16][2];
            i7 = mcol((((f294S[mcol8 & GF2Field.MASK] & 255) ^ ((f294S[(mcol5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f294S[(mcol6 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f294S[(mcol7 >> 24) & GF2Field.MASK] << 24));
            i6 = i16 + 1;
            i8 = iArr[i16][3];
        }
    }

    private void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2, int[][] iArr) {
        int littleEndianToInt = Pack.littleEndianToInt(bArr, i + 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, i + 8);
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, i + 12);
        int i3 = littleEndianToInt ^ iArr[this.ROUNDS][0];
        int i4 = littleEndianToInt2 ^ iArr[this.ROUNDS][1];
        int i5 = littleEndianToInt3 ^ iArr[this.ROUNDS][2];
        int i6 = this.ROUNDS - 1;
        int i7 = littleEndianToInt4;
        int i8 = iArr[this.ROUNDS][3];
        while (true) {
            int i9 = i7 ^ i8;
            if (i6 <= 1) {
                int inv_mcol = inv_mcol((((f295Si[i3 & GF2Field.MASK] & 255) ^ ((f295Si[(i9 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][0];
                int inv_mcol2 = inv_mcol((((f295Si[i4 & GF2Field.MASK] & 255) ^ ((f295Si[(i3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i9 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i5 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][1];
                int inv_mcol3 = inv_mcol((((f295Si[i5 & GF2Field.MASK] & 255) ^ ((f295Si[(i4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i9 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][2];
                int inv_mcol4 = inv_mcol((((f295Si[i9 & GF2Field.MASK] & 255) ^ ((f295Si[(i5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][3];
                int i10 = ((((f295Si[inv_mcol & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol2 >> 24) & GF2Field.MASK] << 24)) ^ iArr[0][0];
                int i11 = ((((f295Si[inv_mcol2 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[0][1];
                int i12 = ((((f295Si[inv_mcol3 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol2 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[0][2];
                Pack.intToLittleEndian(i10, bArr2, i2 + 0);
                Pack.intToLittleEndian(i11, bArr2, i2 + 4);
                Pack.intToLittleEndian(i12, bArr2, i2 + 8);
                Pack.intToLittleEndian(((((f295Si[inv_mcol4 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol2 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol >> 24) & GF2Field.MASK] << 24)) ^ iArr[0][3], bArr2, i2 + 12);
                return;
            }
            int inv_mcol5 = inv_mcol((((f295Si[i3 & GF2Field.MASK] & 255) ^ ((f295Si[(i9 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i4 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][0];
            int inv_mcol6 = inv_mcol((((f295Si[i4 & GF2Field.MASK] & 255) ^ ((f295Si[(i3 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i9 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i5 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][1];
            int inv_mcol7 = inv_mcol((((f295Si[i5 & GF2Field.MASK] & 255) ^ ((f295Si[(i4 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i3 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i9 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i6][2];
            int i13 = i6;
            int i14 = i6 - 1;
            int inv_mcol8 = inv_mcol((((f295Si[i9 & GF2Field.MASK] & 255) ^ ((f295Si[(i5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(i4 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(i3 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i13][3];
            i3 = inv_mcol((((f295Si[inv_mcol5 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol8 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol7 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol6 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i14][0];
            i4 = inv_mcol((((f295Si[inv_mcol6 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol5 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol8 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol7 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i14][1];
            i5 = inv_mcol((((f295Si[inv_mcol7 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol6 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol5 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol8 >> 24) & GF2Field.MASK] << 24)) ^ iArr[i14][2];
            i7 = inv_mcol((((f295Si[inv_mcol8 & GF2Field.MASK] & 255) ^ ((f295Si[(inv_mcol7 >> 8) & GF2Field.MASK] & 255) << 8)) ^ ((f295Si[(inv_mcol6 >> 16) & GF2Field.MASK] & 255) << 16)) ^ (f295Si[(inv_mcol5 >> 24) & GF2Field.MASK] << 24));
            i6 = i14 - 1;
            i8 = iArr[i14][3];
        }
    }
}