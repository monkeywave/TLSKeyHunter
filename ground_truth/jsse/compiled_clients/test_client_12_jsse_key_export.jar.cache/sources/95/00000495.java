package org.bouncycastle.crypto.engines;

import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/TwofishEngine.class */
public final class TwofishEngine implements BlockCipher {

    /* renamed from: P */
    private static final byte[][] f385P = {new byte[]{-87, 103, -77, -24, 4, -3, -93, 118, -102, -110, Byte.MIN_VALUE, 120, -28, -35, -47, 56, 13, -58, 53, -104, 24, -9, -20, 108, 67, 117, 55, 38, -6, 19, -108, 72, -14, -48, -117, 48, -124, 84, -33, 35, 25, 91, 61, 89, -13, -82, -94, -126, 99, 1, -125, 46, -39, 81, -101, 124, -90, -21, -91, -66, 22, 12, -29, 97, -64, -116, 58, -11, 115, 44, 37, 11, -69, 78, -119, 107, 83, 106, -76, -15, -31, -26, -67, 69, -30, -12, -74, 102, -52, -107, 3, 86, -44, 28, 30, -41, -5, -61, -114, -75, -23, -49, -65, -70, -22, 119, 57, -81, 51, -55, 98, 113, -127, 121, 9, -83, 36, -51, -7, -40, -27, -59, -71, 77, 68, 8, -122, -25, -95, 29, -86, -19, 6, 112, -78, -46, 65, 123, -96, 17, 49, -62, 39, -112, 32, -10, 96, -1, -106, 92, -79, -85, -98, -100, 82, 27, 95, -109, 10, -17, -111, -123, 73, -18, 45, 79, -113, 59, 71, -121, 109, 70, -42, 62, 105, 100, 42, -50, -53, 47, -4, -105, 5, 122, -84, Byte.MAX_VALUE, -43, 26, 75, 14, -89, 90, 40, 20, 63, 41, -120, 60, 76, 2, -72, -38, -80, 23, 85, 31, -118, 125, 87, -57, -115, 116, -73, -60, -97, 114, 126, 21, 34, 18, 88, 7, -103, 52, 110, 80, -34, 104, 101, -68, -37, -8, -56, -88, 43, 64, -36, -2, 50, -92, -54, 16, 33, -16, -45, 93, 15, 0, 111, -99, 54, 66, 74, 94, -63, -32}, new byte[]{117, -13, -58, -12, -37, 123, -5, -56, 74, -45, -26, 107, 69, 125, -24, 75, -42, 50, -40, -3, 55, 113, -15, -31, 48, 15, -8, 27, -121, -6, 6, 63, 94, -70, -82, 91, -118, 0, -68, -99, 109, -63, -79, 14, Byte.MIN_VALUE, 93, -46, -43, -96, -124, 7, 20, -75, -112, 44, -93, -78, 115, 76, 84, -110, 116, 54, 81, 56, -80, -67, 90, -4, 96, 98, -106, 108, 66, -9, 16, 124, 40, 39, -116, 19, -107, -100, -57, 36, 70, 59, 112, -54, -29, -123, -53, 17, -48, -109, -72, -90, -125, 32, -1, -97, 119, -61, -52, 3, 111, 8, -65, 64, -25, 43, -30, 121, 12, -86, -126, 65, 58, -22, -71, -28, -102, -92, -105, 126, -38, 122, 23, 102, -108, -95, 29, 61, -16, -34, -77, 11, 114, -89, 28, -17, -47, 83, 62, -113, 51, 38, 95, -20, 118, 42, 73, -127, -120, -18, 33, -60, 26, -21, -39, -59, 57, -103, -51, -83, 49, -117, 1, 24, 35, -35, 31, 78, 45, -7, 72, 79, -14, 101, -114, 120, 92, 88, 25, -115, -27, -104, 87, 103, Byte.MAX_VALUE, 5, 100, -81, 99, -74, -2, -11, -73, 60, -91, -50, -23, 104, 68, -32, 77, 67, 105, 41, 46, -84, 21, 89, -88, 10, -98, 110, 71, -33, 52, 53, 106, -49, -36, 34, -55, -64, -101, -119, -44, -19, -85, 18, -94, 13, 82, -69, 2, 47, -87, -41, 97, 30, -76, 80, 4, -10, -62, 22, 37, -122, 86, 85, 9, -66, -111}};
    private static final int P_00 = 1;
    private static final int P_01 = 0;
    private static final int P_02 = 0;
    private static final int P_03 = 1;
    private static final int P_04 = 1;
    private static final int P_10 = 0;
    private static final int P_11 = 0;
    private static final int P_12 = 1;
    private static final int P_13 = 1;
    private static final int P_14 = 0;
    private static final int P_20 = 1;
    private static final int P_21 = 1;
    private static final int P_22 = 0;
    private static final int P_23 = 0;
    private static final int P_24 = 0;
    private static final int P_30 = 0;
    private static final int P_31 = 1;
    private static final int P_32 = 1;
    private static final int P_33 = 0;
    private static final int P_34 = 1;
    private static final int GF256_FDBK = 361;
    private static final int GF256_FDBK_2 = 180;
    private static final int GF256_FDBK_4 = 90;
    private static final int RS_GF_FDBK = 333;
    private static final int ROUNDS = 16;
    private static final int MAX_ROUNDS = 16;
    private static final int BLOCK_SIZE = 16;
    private static final int MAX_KEY_BITS = 256;
    private static final int INPUT_WHITEN = 0;
    private static final int OUTPUT_WHITEN = 4;
    private static final int ROUND_SUBKEYS = 8;
    private static final int TOTAL_SUBKEYS = 40;
    private static final int SK_STEP = 33686018;
    private static final int SK_BUMP = 16843009;
    private static final int SK_ROTL = 9;
    private int[] gSubKeys;
    private int[] gSBox;
    private boolean encrypting = false;
    private int[] gMDS0 = new int[256];
    private int[] gMDS1 = new int[256];
    private int[] gMDS2 = new int[256];
    private int[] gMDS3 = new int[256];
    private int k64Cnt = 0;
    private byte[] workingKey = null;

    public TwofishEngine() {
        int[] iArr = new int[2];
        int[] iArr2 = new int[2];
        int[] iArr3 = new int[2];
        for (int i = 0; i < 256; i++) {
            int i2 = f385P[0][i] & 255;
            iArr[0] = i2;
            iArr2[0] = Mx_X(i2) & GF2Field.MASK;
            iArr3[0] = Mx_Y(i2) & GF2Field.MASK;
            int i3 = f385P[1][i] & 255;
            iArr[1] = i3;
            iArr2[1] = Mx_X(i3) & GF2Field.MASK;
            iArr3[1] = Mx_Y(i3) & GF2Field.MASK;
            this.gMDS0[i] = iArr[1] | (iArr2[1] << 8) | (iArr3[1] << 16) | (iArr3[1] << 24);
            this.gMDS1[i] = iArr3[0] | (iArr3[0] << 8) | (iArr2[0] << 16) | (iArr[0] << 24);
            this.gMDS2[i] = iArr2[1] | (iArr3[1] << 8) | (iArr[1] << 16) | (iArr3[1] << 24);
            this.gMDS3[i] = iArr2[0] | (iArr[0] << 8) | (iArr3[0] << 16) | (iArr2[0] << 24);
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to Twofish init - " + cipherParameters.getClass().getName());
        }
        this.encrypting = z;
        this.workingKey = ((KeyParameter) cipherParameters).getKey();
        switch (this.workingKey.length * 8) {
            case 128:
            case 192:
            case 256:
                this.k64Cnt = this.workingKey.length / 8;
                setKey(this.workingKey);
                return;
            default:
                throw new IllegalArgumentException("Key length not 128/192/256 bits.");
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Twofish";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this.workingKey == null) {
            throw new IllegalStateException("Twofish not initialised");
        }
        if (i + 16 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + 16 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.encrypting) {
            encryptBlock(bArr, i, bArr2, i2);
            return 16;
        }
        decryptBlock(bArr, i, bArr2, i2);
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        if (this.workingKey != null) {
            setKey(this.workingKey);
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private void setKey(byte[] bArr) {
        int[] iArr = new int[4];
        int[] iArr2 = new int[4];
        int[] iArr3 = new int[4];
        this.gSubKeys = new int[40];
        for (int i = 0; i < this.k64Cnt; i++) {
            int i2 = i * 8;
            iArr[i] = Pack.littleEndianToInt(bArr, i2);
            iArr2[i] = Pack.littleEndianToInt(bArr, i2 + 4);
            iArr3[(this.k64Cnt - 1) - i] = RS_MDS_Encode(iArr[i], iArr2[i]);
        }
        for (int i3 = 0; i3 < 20; i3++) {
            int i4 = i3 * SK_STEP;
            int F32 = F32(i4, iArr);
            int rotateLeft = Integers.rotateLeft(F32(i4 + SK_BUMP, iArr2), 8);
            int i5 = F32 + rotateLeft;
            this.gSubKeys[i3 * 2] = i5;
            int i6 = i5 + rotateLeft;
            this.gSubKeys[(i3 * 2) + 1] = (i6 << 9) | (i6 >>> 23);
        }
        int i7 = iArr3[0];
        int i8 = iArr3[1];
        int i9 = iArr3[2];
        int i10 = iArr3[3];
        this.gSBox = new int[1024];
        for (int i11 = 0; i11 < 256; i11++) {
            int i12 = i11;
            int i13 = i12;
            int i14 = i12;
            int i15 = i12;
            int i16 = i12;
            switch (this.k64Cnt & 3) {
                case 0:
                    i16 = (f385P[1][i16] & 255) ^ m35b0(i10);
                    i15 = (f385P[0][i15] & 255) ^ m34b1(i10);
                    i14 = (f385P[0][i14] & 255) ^ m33b2(i10);
                    i13 = (f385P[1][i13] & 255) ^ m32b3(i10);
                    i16 = (f385P[1][i16] & 255) ^ m35b0(i9);
                    i15 = (f385P[1][i15] & 255) ^ m34b1(i9);
                    i14 = (f385P[0][i14] & 255) ^ m33b2(i9);
                    i13 = (f385P[0][i13] & 255) ^ m32b3(i9);
                    break;
                case 1:
                    this.gSBox[i11 * 2] = this.gMDS0[(f385P[0][i16] & 255) ^ m35b0(i7)];
                    this.gSBox[(i11 * 2) + 1] = this.gMDS1[(f385P[0][i15] & 255) ^ m34b1(i7)];
                    this.gSBox[(i11 * 2) + 512] = this.gMDS2[(f385P[1][i14] & 255) ^ m33b2(i7)];
                    this.gSBox[(i11 * 2) + 513] = this.gMDS3[(f385P[1][i13] & 255) ^ m32b3(i7)];
                    continue;
                case 2:
                    break;
                case 3:
                    i16 = (f385P[1][i16] & 255) ^ m35b0(i9);
                    i15 = (f385P[1][i15] & 255) ^ m34b1(i9);
                    i14 = (f385P[0][i14] & 255) ^ m33b2(i9);
                    i13 = (f385P[0][i13] & 255) ^ m32b3(i9);
                    break;
                default:
            }
            this.gSBox[i11 * 2] = this.gMDS0[(f385P[0][(f385P[0][i16] & 255) ^ m35b0(i8)] & 255) ^ m35b0(i7)];
            this.gSBox[(i11 * 2) + 1] = this.gMDS1[(f385P[0][(f385P[1][i15] & 255) ^ m34b1(i8)] & 255) ^ m34b1(i7)];
            this.gSBox[(i11 * 2) + 512] = this.gMDS2[(f385P[1][(f385P[0][i14] & 255) ^ m33b2(i8)] & 255) ^ m33b2(i7)];
            this.gSBox[(i11 * 2) + 513] = this.gMDS3[(f385P[1][(f385P[1][i13] & 255) ^ m32b3(i8)] & 255) ^ m32b3(i7)];
        }
    }

    private void encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int littleEndianToInt = Pack.littleEndianToInt(bArr, i) ^ this.gSubKeys[0];
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + 4) ^ this.gSubKeys[1];
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, i + 8) ^ this.gSubKeys[2];
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, i + 12) ^ this.gSubKeys[3];
        int i3 = 8;
        for (int i4 = 0; i4 < 16; i4 += 2) {
            int Fe32_0 = Fe32_0(littleEndianToInt);
            int Fe32_3 = Fe32_3(littleEndianToInt2);
            int i5 = i3;
            int i6 = i3 + 1;
            littleEndianToInt3 = Integers.rotateRight(littleEndianToInt3 ^ ((Fe32_0 + Fe32_3) + this.gSubKeys[i5]), 1);
            int i7 = i6 + 1;
            littleEndianToInt4 = Integers.rotateLeft(littleEndianToInt4, 1) ^ ((Fe32_0 + (2 * Fe32_3)) + this.gSubKeys[i6]);
            int Fe32_02 = Fe32_0(littleEndianToInt3);
            int Fe32_32 = Fe32_3(littleEndianToInt4);
            int i8 = i7 + 1;
            littleEndianToInt = Integers.rotateRight(littleEndianToInt ^ ((Fe32_02 + Fe32_32) + this.gSubKeys[i7]), 1);
            i3 = i8 + 1;
            littleEndianToInt2 = Integers.rotateLeft(littleEndianToInt2, 1) ^ ((Fe32_02 + (2 * Fe32_32)) + this.gSubKeys[i8]);
        }
        Pack.intToLittleEndian(littleEndianToInt3 ^ this.gSubKeys[4], bArr2, i2);
        Pack.intToLittleEndian(littleEndianToInt4 ^ this.gSubKeys[5], bArr2, i2 + 4);
        Pack.intToLittleEndian(littleEndianToInt ^ this.gSubKeys[6], bArr2, i2 + 8);
        Pack.intToLittleEndian(littleEndianToInt2 ^ this.gSubKeys[7], bArr2, i2 + 12);
    }

    private void decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int littleEndianToInt = Pack.littleEndianToInt(bArr, i) ^ this.gSubKeys[4];
        int littleEndianToInt2 = Pack.littleEndianToInt(bArr, i + 4) ^ this.gSubKeys[5];
        int littleEndianToInt3 = Pack.littleEndianToInt(bArr, i + 8) ^ this.gSubKeys[6];
        int littleEndianToInt4 = Pack.littleEndianToInt(bArr, i + 12) ^ this.gSubKeys[7];
        int i3 = 39;
        for (int i4 = 0; i4 < 16; i4 += 2) {
            int Fe32_0 = Fe32_0(littleEndianToInt);
            int Fe32_3 = Fe32_3(littleEndianToInt2);
            int i5 = i3;
            int i6 = i3 - 1;
            int i7 = littleEndianToInt4 ^ ((Fe32_0 + (2 * Fe32_3)) + this.gSubKeys[i5]);
            int i8 = i6 - 1;
            littleEndianToInt3 = Integers.rotateLeft(littleEndianToInt3, 1) ^ ((Fe32_0 + Fe32_3) + this.gSubKeys[i6]);
            littleEndianToInt4 = Integers.rotateRight(i7, 1);
            int Fe32_02 = Fe32_0(littleEndianToInt3);
            int Fe32_32 = Fe32_3(littleEndianToInt4);
            int i9 = i8 - 1;
            int i10 = littleEndianToInt2 ^ ((Fe32_02 + (2 * Fe32_32)) + this.gSubKeys[i8]);
            i3 = i9 - 1;
            littleEndianToInt = Integers.rotateLeft(littleEndianToInt, 1) ^ ((Fe32_02 + Fe32_32) + this.gSubKeys[i9]);
            littleEndianToInt2 = Integers.rotateRight(i10, 1);
        }
        Pack.intToLittleEndian(littleEndianToInt3 ^ this.gSubKeys[0], bArr2, i2);
        Pack.intToLittleEndian(littleEndianToInt4 ^ this.gSubKeys[1], bArr2, i2 + 4);
        Pack.intToLittleEndian(littleEndianToInt ^ this.gSubKeys[2], bArr2, i2 + 8);
        Pack.intToLittleEndian(littleEndianToInt2 ^ this.gSubKeys[3], bArr2, i2 + 12);
    }

    /* JADX WARN: Can't fix incorrect switch cases order, some code will duplicate */
    private int F32(int i, int[] iArr) {
        int m35b0 = m35b0(i);
        int m34b1 = m34b1(i);
        int m33b2 = m33b2(i);
        int m32b3 = m32b3(i);
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = 0;
        switch (this.k64Cnt & 3) {
            case 0:
                m35b0 = (f385P[1][m35b0] & 255) ^ m35b0(i5);
                m34b1 = (f385P[0][m34b1] & 255) ^ m34b1(i5);
                m33b2 = (f385P[0][m33b2] & 255) ^ m33b2(i5);
                m32b3 = (f385P[1][m32b3] & 255) ^ m32b3(i5);
                m35b0 = (f385P[1][m35b0] & 255) ^ m35b0(i4);
                m34b1 = (f385P[1][m34b1] & 255) ^ m34b1(i4);
                m33b2 = (f385P[0][m33b2] & 255) ^ m33b2(i4);
                m32b3 = (f385P[0][m32b3] & 255) ^ m32b3(i4);
                i6 = ((this.gMDS0[(f385P[0][(f385P[0][m35b0] & 255) ^ m35b0(i3)] & 255) ^ m35b0(i2)] ^ this.gMDS1[(f385P[0][(f385P[1][m34b1] & 255) ^ m34b1(i3)] & 255) ^ m34b1(i2)]) ^ this.gMDS2[(f385P[1][(f385P[0][m33b2] & 255) ^ m33b2(i3)] & 255) ^ m33b2(i2)]) ^ this.gMDS3[(f385P[1][(f385P[1][m32b3] & 255) ^ m32b3(i3)] & 255) ^ m32b3(i2)];
                break;
            case 1:
                i6 = ((this.gMDS0[(f385P[0][m35b0] & 255) ^ m35b0(i2)] ^ this.gMDS1[(f385P[0][m34b1] & 255) ^ m34b1(i2)]) ^ this.gMDS2[(f385P[1][m33b2] & 255) ^ m33b2(i2)]) ^ this.gMDS3[(f385P[1][m32b3] & 255) ^ m32b3(i2)];
                break;
            case 2:
                i6 = ((this.gMDS0[(f385P[0][(f385P[0][m35b0] & 255) ^ m35b0(i3)] & 255) ^ m35b0(i2)] ^ this.gMDS1[(f385P[0][(f385P[1][m34b1] & 255) ^ m34b1(i3)] & 255) ^ m34b1(i2)]) ^ this.gMDS2[(f385P[1][(f385P[0][m33b2] & 255) ^ m33b2(i3)] & 255) ^ m33b2(i2)]) ^ this.gMDS3[(f385P[1][(f385P[1][m32b3] & 255) ^ m32b3(i3)] & 255) ^ m32b3(i2)];
                break;
            case 3:
                m35b0 = (f385P[1][m35b0] & 255) ^ m35b0(i4);
                m34b1 = (f385P[1][m34b1] & 255) ^ m34b1(i4);
                m33b2 = (f385P[0][m33b2] & 255) ^ m33b2(i4);
                m32b3 = (f385P[0][m32b3] & 255) ^ m32b3(i4);
                i6 = ((this.gMDS0[(f385P[0][(f385P[0][m35b0] & 255) ^ m35b0(i3)] & 255) ^ m35b0(i2)] ^ this.gMDS1[(f385P[0][(f385P[1][m34b1] & 255) ^ m34b1(i3)] & 255) ^ m34b1(i2)]) ^ this.gMDS2[(f385P[1][(f385P[0][m33b2] & 255) ^ m33b2(i3)] & 255) ^ m33b2(i2)]) ^ this.gMDS3[(f385P[1][(f385P[1][m32b3] & 255) ^ m32b3(i3)] & 255) ^ m32b3(i2)];
                break;
        }
        return i6;
    }

    private int RS_MDS_Encode(int i, int i2) {
        int i3 = i2;
        for (int i4 = 0; i4 < 4; i4++) {
            i3 = RS_rem(i3);
        }
        int i5 = i3 ^ i;
        for (int i6 = 0; i6 < 4; i6++) {
            i5 = RS_rem(i5);
        }
        return i5;
    }

    private int RS_rem(int i) {
        int i2 = (i >>> 24) & GF2Field.MASK;
        int i3 = ((i2 << 1) ^ ((i2 & 128) != 0 ? 333 : 0)) & GF2Field.MASK;
        int i4 = ((i2 >>> 1) ^ ((i2 & 1) != 0 ? Opcode.IF_ACMPNE : 0)) ^ i3;
        return ((((i << 8) ^ (i4 << 24)) ^ (i3 << 16)) ^ (i4 << 8)) ^ i2;
    }

    private int LFSR1(int i) {
        return (i >> 1) ^ ((i & 1) != 0 ? 180 : 0);
    }

    private int LFSR2(int i) {
        return ((i >> 2) ^ ((i & 2) != 0 ? 180 : 0)) ^ ((i & 1) != 0 ? 90 : 0);
    }

    private int Mx_X(int i) {
        return i ^ LFSR2(i);
    }

    private int Mx_Y(int i) {
        return (i ^ LFSR1(i)) ^ LFSR2(i);
    }

    /* renamed from: b0 */
    private int m35b0(int i) {
        return i & GF2Field.MASK;
    }

    /* renamed from: b1 */
    private int m34b1(int i) {
        return (i >>> 8) & GF2Field.MASK;
    }

    /* renamed from: b2 */
    private int m33b2(int i) {
        return (i >>> 16) & GF2Field.MASK;
    }

    /* renamed from: b3 */
    private int m32b3(int i) {
        return (i >>> 24) & GF2Field.MASK;
    }

    private int Fe32_0(int i) {
        return ((this.gSBox[0 + (2 * (i & GF2Field.MASK))] ^ this.gSBox[1 + (2 * ((i >>> 8) & GF2Field.MASK))]) ^ this.gSBox[512 + (2 * ((i >>> 16) & GF2Field.MASK))]) ^ this.gSBox[513 + (2 * ((i >>> 24) & GF2Field.MASK))];
    }

    private int Fe32_3(int i) {
        return ((this.gSBox[0 + (2 * ((i >>> 24) & GF2Field.MASK))] ^ this.gSBox[1 + (2 * (i & GF2Field.MASK))]) ^ this.gSBox[512 + (2 * ((i >>> 8) & GF2Field.MASK))]) ^ this.gSBox[513 + (2 * ((i >>> 16) & GF2Field.MASK))];
    }
}