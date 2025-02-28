package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/CamelliaLightEngine.class */
public class CamelliaLightEngine implements BlockCipher {
    private static final int BLOCK_SIZE = 16;
    private static final int MASK8 = 255;
    private boolean initialized;
    private boolean _keyis128;
    private int[] subkey = new int[96];

    /* renamed from: kw */
    private int[] f318kw = new int[8];

    /* renamed from: ke */
    private int[] f319ke = new int[12];
    private int[] state = new int[4];
    private static final int[] SIGMA = {-1600231809, 1003262091, -1233459112, 1286239154, -957401297, -380665154, 1426019237, -237801700, 283453434, -563598051, -1336506174, -1276722691};
    private static final byte[] SBOX1 = {112, -126, 44, -20, -77, 39, -64, -27, -28, -123, 87, 53, -22, 12, -82, 65, 35, -17, 107, -109, 69, 25, -91, 33, -19, 14, 79, 78, 29, 101, -110, -67, -122, -72, -81, -113, 124, -21, 31, -50, 62, 48, -36, 95, 94, -59, 11, 26, -90, -31, 57, -54, -43, 71, 93, 61, -39, 1, 90, -42, 81, 86, 108, 77, -117, 13, -102, 102, -5, -52, -80, 45, 116, 18, 43, 32, -16, -79, -124, -103, -33, 76, -53, -62, 52, 126, 118, 5, 109, -73, -87, 49, -47, 23, 4, -41, 20, 88, 58, 97, -34, 27, 17, 28, 50, 15, -100, 22, 83, 24, -14, 34, -2, 68, -49, -78, -61, -75, 122, -111, 36, 8, -24, -88, 96, -4, 105, 80, -86, -48, -96, 125, -95, -119, 98, -105, 84, 91, 30, -107, -32, -1, 100, -46, 16, -60, 0, 72, -93, -9, 117, -37, -118, 3, -26, -38, 9, 63, -35, -108, -121, 92, -125, 2, -51, 74, -112, 51, 115, 103, -10, -13, -99, Byte.MAX_VALUE, -65, -30, 82, -101, -40, 38, -56, 55, -58, 59, -127, -106, 111, 75, 19, -66, 99, 46, -23, 121, -89, -116, -97, 110, -68, -114, 41, -11, -7, -74, 47, -3, -76, 89, 120, -104, 6, 106, -25, 70, 113, -70, -44, 37, -85, 66, -120, -94, -115, -6, 114, 7, -71, 85, -8, -18, -84, 10, 54, 73, 42, 104, 60, 56, -15, -92, 64, 40, -45, 123, -69, -55, 67, -63, 21, -29, -83, -12, 119, -57, Byte.MIN_VALUE, -98};

    private static int rightRotate(int i, int i2) {
        return (i >>> i2) + (i << (32 - i2));
    }

    private static int leftRotate(int i, int i2) {
        return (i << i2) + (i >>> (32 - i2));
    }

    private static void roldq(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        iArr2[0 + i3] = (iArr[0 + i2] << i) | (iArr[1 + i2] >>> (32 - i));
        iArr2[1 + i3] = (iArr[1 + i2] << i) | (iArr[2 + i2] >>> (32 - i));
        iArr2[2 + i3] = (iArr[2 + i2] << i) | (iArr[3 + i2] >>> (32 - i));
        iArr2[3 + i3] = (iArr[3 + i2] << i) | (iArr[0 + i2] >>> (32 - i));
        iArr[0 + i2] = iArr2[0 + i3];
        iArr[1 + i2] = iArr2[1 + i3];
        iArr[2 + i2] = iArr2[2 + i3];
        iArr[3 + i2] = iArr2[3 + i3];
    }

    private static void decroldq(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        iArr2[2 + i3] = (iArr[0 + i2] << i) | (iArr[1 + i2] >>> (32 - i));
        iArr2[3 + i3] = (iArr[1 + i2] << i) | (iArr[2 + i2] >>> (32 - i));
        iArr2[0 + i3] = (iArr[2 + i2] << i) | (iArr[3 + i2] >>> (32 - i));
        iArr2[1 + i3] = (iArr[3 + i2] << i) | (iArr[0 + i2] >>> (32 - i));
        iArr[0 + i2] = iArr2[2 + i3];
        iArr[1 + i2] = iArr2[3 + i3];
        iArr[2 + i2] = iArr2[0 + i3];
        iArr[3 + i2] = iArr2[1 + i3];
    }

    private static void roldqo32(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        iArr2[0 + i3] = (iArr[1 + i2] << (i - 32)) | (iArr[2 + i2] >>> (64 - i));
        iArr2[1 + i3] = (iArr[2 + i2] << (i - 32)) | (iArr[3 + i2] >>> (64 - i));
        iArr2[2 + i3] = (iArr[3 + i2] << (i - 32)) | (iArr[0 + i2] >>> (64 - i));
        iArr2[3 + i3] = (iArr[0 + i2] << (i - 32)) | (iArr[1 + i2] >>> (64 - i));
        iArr[0 + i2] = iArr2[0 + i3];
        iArr[1 + i2] = iArr2[1 + i3];
        iArr[2 + i2] = iArr2[2 + i3];
        iArr[3 + i2] = iArr2[3 + i3];
    }

    private static void decroldqo32(int i, int[] iArr, int i2, int[] iArr2, int i3) {
        iArr2[2 + i3] = (iArr[1 + i2] << (i - 32)) | (iArr[2 + i2] >>> (64 - i));
        iArr2[3 + i3] = (iArr[2 + i2] << (i - 32)) | (iArr[3 + i2] >>> (64 - i));
        iArr2[0 + i3] = (iArr[3 + i2] << (i - 32)) | (iArr[0 + i2] >>> (64 - i));
        iArr2[1 + i3] = (iArr[0 + i2] << (i - 32)) | (iArr[1 + i2] >>> (64 - i));
        iArr[0 + i2] = iArr2[2 + i3];
        iArr[1 + i2] = iArr2[3 + i3];
        iArr[2 + i2] = iArr2[0 + i3];
        iArr[3 + i2] = iArr2[1 + i3];
    }

    private int bytes2int(byte[] bArr, int i) {
        int i2 = 0;
        for (int i3 = 0; i3 < 4; i3++) {
            i2 = (i2 << 8) + (bArr[i3 + i] & 255);
        }
        return i2;
    }

    private void int2bytes(int i, byte[] bArr, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            bArr[(3 - i3) + i2] = (byte) i;
            i >>>= 8;
        }
    }

    private byte lRot8(byte b, int i) {
        return (byte) ((b << i) | ((b & 255) >>> (8 - i)));
    }

    private int sbox2(int i) {
        return lRot8(SBOX1[i], 1) & 255;
    }

    private int sbox3(int i) {
        return lRot8(SBOX1[i], 7) & 255;
    }

    private int sbox4(int i) {
        return SBOX1[lRot8((byte) i, 1) & 255] & 255;
    }

    private void camelliaF2(int[] iArr, int[] iArr2, int i) {
        int i2 = iArr[0] ^ iArr2[0 + i];
        int sbox4 = sbox4(i2 & 255) | (sbox3((i2 >>> 8) & 255) << 8) | (sbox2((i2 >>> 16) & 255) << 16) | ((SBOX1[(i2 >>> 24) & 255] & 255) << 24);
        int i3 = iArr[1] ^ iArr2[1 + i];
        int leftRotate = leftRotate((SBOX1[i3 & 255] & 255) | (sbox4((i3 >>> 8) & 255) << 8) | (sbox3((i3 >>> 16) & 255) << 16) | (sbox2((i3 >>> 24) & 255) << 24), 8);
        int i4 = sbox4 ^ leftRotate;
        int leftRotate2 = leftRotate(leftRotate, 8) ^ i4;
        int rightRotate = rightRotate(i4, 8) ^ leftRotate2;
        iArr[2] = iArr[2] ^ (leftRotate(leftRotate2, 16) ^ rightRotate);
        iArr[3] = iArr[3] ^ leftRotate(rightRotate, 8);
        int i5 = iArr[2] ^ iArr2[2 + i];
        int sbox42 = sbox4(i5 & 255) | (sbox3((i5 >>> 8) & 255) << 8) | (sbox2((i5 >>> 16) & 255) << 16) | ((SBOX1[(i5 >>> 24) & 255] & 255) << 24);
        int i6 = iArr[3] ^ iArr2[3 + i];
        int leftRotate3 = leftRotate((SBOX1[i6 & 255] & 255) | (sbox4((i6 >>> 8) & 255) << 8) | (sbox3((i6 >>> 16) & 255) << 16) | (sbox2((i6 >>> 24) & 255) << 24), 8);
        int i7 = sbox42 ^ leftRotate3;
        int leftRotate4 = leftRotate(leftRotate3, 8) ^ i7;
        int rightRotate2 = rightRotate(i7, 8) ^ leftRotate4;
        iArr[0] = iArr[0] ^ (leftRotate(leftRotate4, 16) ^ rightRotate2);
        iArr[1] = iArr[1] ^ leftRotate(rightRotate2, 8);
    }

    private void camelliaFLs(int[] iArr, int[] iArr2, int i) {
        iArr[1] = iArr[1] ^ leftRotate(iArr[0] & iArr2[0 + i], 1);
        iArr[0] = iArr[0] ^ (iArr2[1 + i] | iArr[1]);
        iArr[2] = iArr[2] ^ (iArr2[3 + i] | iArr[3]);
        iArr[3] = iArr[3] ^ leftRotate(iArr2[2 + i] & iArr[2], 1);
    }

    private void setKey(boolean z, byte[] bArr) {
        int[] iArr = new int[8];
        int[] iArr2 = new int[4];
        int[] iArr3 = new int[4];
        int[] iArr4 = new int[4];
        switch (bArr.length) {
            case 16:
                this._keyis128 = true;
                iArr[0] = bytes2int(bArr, 0);
                iArr[1] = bytes2int(bArr, 4);
                iArr[2] = bytes2int(bArr, 8);
                iArr[3] = bytes2int(bArr, 12);
                iArr[7] = 0;
                iArr[6] = 0;
                iArr[5] = 0;
                iArr[4] = 0;
                break;
            case 24:
                iArr[0] = bytes2int(bArr, 0);
                iArr[1] = bytes2int(bArr, 4);
                iArr[2] = bytes2int(bArr, 8);
                iArr[3] = bytes2int(bArr, 12);
                iArr[4] = bytes2int(bArr, 16);
                iArr[5] = bytes2int(bArr, 20);
                iArr[6] = iArr[4] ^ (-1);
                iArr[7] = iArr[5] ^ (-1);
                this._keyis128 = false;
                break;
            case 32:
                iArr[0] = bytes2int(bArr, 0);
                iArr[1] = bytes2int(bArr, 4);
                iArr[2] = bytes2int(bArr, 8);
                iArr[3] = bytes2int(bArr, 12);
                iArr[4] = bytes2int(bArr, 16);
                iArr[5] = bytes2int(bArr, 20);
                iArr[6] = bytes2int(bArr, 24);
                iArr[7] = bytes2int(bArr, 28);
                this._keyis128 = false;
                break;
            default:
                throw new IllegalArgumentException("key sizes are only 16/24/32 bytes.");
        }
        for (int i = 0; i < 4; i++) {
            iArr2[i] = iArr[i] ^ iArr[i + 4];
        }
        camelliaF2(iArr2, SIGMA, 0);
        for (int i2 = 0; i2 < 4; i2++) {
            int i3 = i2;
            iArr2[i3] = iArr2[i3] ^ iArr[i2];
        }
        camelliaF2(iArr2, SIGMA, 4);
        if (this._keyis128) {
            if (z) {
                this.f318kw[0] = iArr[0];
                this.f318kw[1] = iArr[1];
                this.f318kw[2] = iArr[2];
                this.f318kw[3] = iArr[3];
                roldq(15, iArr, 0, this.subkey, 4);
                roldq(30, iArr, 0, this.subkey, 12);
                roldq(15, iArr, 0, iArr4, 0);
                this.subkey[18] = iArr4[2];
                this.subkey[19] = iArr4[3];
                roldq(17, iArr, 0, this.f319ke, 4);
                roldq(17, iArr, 0, this.subkey, 24);
                roldq(17, iArr, 0, this.subkey, 32);
                this.subkey[0] = iArr2[0];
                this.subkey[1] = iArr2[1];
                this.subkey[2] = iArr2[2];
                this.subkey[3] = iArr2[3];
                roldq(15, iArr2, 0, this.subkey, 8);
                roldq(15, iArr2, 0, this.f319ke, 0);
                roldq(15, iArr2, 0, iArr4, 0);
                this.subkey[16] = iArr4[0];
                this.subkey[17] = iArr4[1];
                roldq(15, iArr2, 0, this.subkey, 20);
                roldqo32(34, iArr2, 0, this.subkey, 28);
                roldq(17, iArr2, 0, this.f318kw, 4);
                return;
            }
            this.f318kw[4] = iArr[0];
            this.f318kw[5] = iArr[1];
            this.f318kw[6] = iArr[2];
            this.f318kw[7] = iArr[3];
            decroldq(15, iArr, 0, this.subkey, 28);
            decroldq(30, iArr, 0, this.subkey, 20);
            decroldq(15, iArr, 0, iArr4, 0);
            this.subkey[16] = iArr4[0];
            this.subkey[17] = iArr4[1];
            decroldq(17, iArr, 0, this.f319ke, 0);
            decroldq(17, iArr, 0, this.subkey, 8);
            decroldq(17, iArr, 0, this.subkey, 0);
            this.subkey[34] = iArr2[0];
            this.subkey[35] = iArr2[1];
            this.subkey[32] = iArr2[2];
            this.subkey[33] = iArr2[3];
            decroldq(15, iArr2, 0, this.subkey, 24);
            decroldq(15, iArr2, 0, this.f319ke, 4);
            decroldq(15, iArr2, 0, iArr4, 0);
            this.subkey[18] = iArr4[2];
            this.subkey[19] = iArr4[3];
            decroldq(15, iArr2, 0, this.subkey, 12);
            decroldqo32(34, iArr2, 0, this.subkey, 4);
            roldq(17, iArr2, 0, this.f318kw, 0);
            return;
        }
        for (int i4 = 0; i4 < 4; i4++) {
            iArr3[i4] = iArr2[i4] ^ iArr[i4 + 4];
        }
        camelliaF2(iArr3, SIGMA, 8);
        if (z) {
            this.f318kw[0] = iArr[0];
            this.f318kw[1] = iArr[1];
            this.f318kw[2] = iArr[2];
            this.f318kw[3] = iArr[3];
            roldqo32(45, iArr, 0, this.subkey, 16);
            roldq(15, iArr, 0, this.f319ke, 4);
            roldq(17, iArr, 0, this.subkey, 32);
            roldqo32(34, iArr, 0, this.subkey, 44);
            roldq(15, iArr, 4, this.subkey, 4);
            roldq(15, iArr, 4, this.f319ke, 0);
            roldq(30, iArr, 4, this.subkey, 24);
            roldqo32(34, iArr, 4, this.subkey, 36);
            roldq(15, iArr2, 0, this.subkey, 8);
            roldq(30, iArr2, 0, this.subkey, 20);
            this.f319ke[8] = iArr2[1];
            this.f319ke[9] = iArr2[2];
            this.f319ke[10] = iArr2[3];
            this.f319ke[11] = iArr2[0];
            roldqo32(49, iArr2, 0, this.subkey, 40);
            this.subkey[0] = iArr3[0];
            this.subkey[1] = iArr3[1];
            this.subkey[2] = iArr3[2];
            this.subkey[3] = iArr3[3];
            roldq(30, iArr3, 0, this.subkey, 12);
            roldq(30, iArr3, 0, this.subkey, 28);
            roldqo32(51, iArr3, 0, this.f318kw, 4);
            return;
        }
        this.f318kw[4] = iArr[0];
        this.f318kw[5] = iArr[1];
        this.f318kw[6] = iArr[2];
        this.f318kw[7] = iArr[3];
        decroldqo32(45, iArr, 0, this.subkey, 28);
        decroldq(15, iArr, 0, this.f319ke, 4);
        decroldq(17, iArr, 0, this.subkey, 12);
        decroldqo32(34, iArr, 0, this.subkey, 0);
        decroldq(15, iArr, 4, this.subkey, 40);
        decroldq(15, iArr, 4, this.f319ke, 8);
        decroldq(30, iArr, 4, this.subkey, 20);
        decroldqo32(34, iArr, 4, this.subkey, 8);
        decroldq(15, iArr2, 0, this.subkey, 36);
        decroldq(30, iArr2, 0, this.subkey, 24);
        this.f319ke[2] = iArr2[1];
        this.f319ke[3] = iArr2[2];
        this.f319ke[0] = iArr2[3];
        this.f319ke[1] = iArr2[0];
        decroldqo32(49, iArr2, 0, this.subkey, 4);
        this.subkey[46] = iArr3[0];
        this.subkey[47] = iArr3[1];
        this.subkey[44] = iArr3[2];
        this.subkey[45] = iArr3[3];
        decroldq(30, iArr3, 0, this.subkey, 32);
        decroldq(30, iArr3, 0, this.subkey, 16);
        roldqo32(51, iArr3, 0, this.f318kw, 0);
    }

    private int processBlock128(byte[] bArr, int i, byte[] bArr2, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            this.state[i3] = bytes2int(bArr, i + (i3 * 4));
            int[] iArr = this.state;
            int i4 = i3;
            iArr[i4] = iArr[i4] ^ this.f318kw[i3];
        }
        camelliaF2(this.state, this.subkey, 0);
        camelliaF2(this.state, this.subkey, 4);
        camelliaF2(this.state, this.subkey, 8);
        camelliaFLs(this.state, this.f319ke, 0);
        camelliaF2(this.state, this.subkey, 12);
        camelliaF2(this.state, this.subkey, 16);
        camelliaF2(this.state, this.subkey, 20);
        camelliaFLs(this.state, this.f319ke, 4);
        camelliaF2(this.state, this.subkey, 24);
        camelliaF2(this.state, this.subkey, 28);
        camelliaF2(this.state, this.subkey, 32);
        int[] iArr2 = this.state;
        iArr2[2] = iArr2[2] ^ this.f318kw[4];
        int[] iArr3 = this.state;
        iArr3[3] = iArr3[3] ^ this.f318kw[5];
        int[] iArr4 = this.state;
        iArr4[0] = iArr4[0] ^ this.f318kw[6];
        int[] iArr5 = this.state;
        iArr5[1] = iArr5[1] ^ this.f318kw[7];
        int2bytes(this.state[2], bArr2, i2);
        int2bytes(this.state[3], bArr2, i2 + 4);
        int2bytes(this.state[0], bArr2, i2 + 8);
        int2bytes(this.state[1], bArr2, i2 + 12);
        return 16;
    }

    private int processBlock192or256(byte[] bArr, int i, byte[] bArr2, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            this.state[i3] = bytes2int(bArr, i + (i3 * 4));
            int[] iArr = this.state;
            int i4 = i3;
            iArr[i4] = iArr[i4] ^ this.f318kw[i3];
        }
        camelliaF2(this.state, this.subkey, 0);
        camelliaF2(this.state, this.subkey, 4);
        camelliaF2(this.state, this.subkey, 8);
        camelliaFLs(this.state, this.f319ke, 0);
        camelliaF2(this.state, this.subkey, 12);
        camelliaF2(this.state, this.subkey, 16);
        camelliaF2(this.state, this.subkey, 20);
        camelliaFLs(this.state, this.f319ke, 4);
        camelliaF2(this.state, this.subkey, 24);
        camelliaF2(this.state, this.subkey, 28);
        camelliaF2(this.state, this.subkey, 32);
        camelliaFLs(this.state, this.f319ke, 8);
        camelliaF2(this.state, this.subkey, 36);
        camelliaF2(this.state, this.subkey, 40);
        camelliaF2(this.state, this.subkey, 44);
        int[] iArr2 = this.state;
        iArr2[2] = iArr2[2] ^ this.f318kw[4];
        int[] iArr3 = this.state;
        iArr3[3] = iArr3[3] ^ this.f318kw[5];
        int[] iArr4 = this.state;
        iArr4[0] = iArr4[0] ^ this.f318kw[6];
        int[] iArr5 = this.state;
        iArr5[1] = iArr5[1] ^ this.f318kw[7];
        int2bytes(this.state[2], bArr2, i2);
        int2bytes(this.state[3], bArr2, i2 + 4);
        int2bytes(this.state[0], bArr2, i2 + 8);
        int2bytes(this.state[1], bArr2, i2 + 12);
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Camellia";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("only simple KeyParameter expected.");
        }
        setKey(z, ((KeyParameter) cipherParameters).getKey());
        this.initialized = true;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws IllegalStateException {
        if (this.initialized) {
            if (i + 16 > bArr.length) {
                throw new DataLengthException("input buffer too short");
            }
            if (i2 + 16 > bArr2.length) {
                throw new OutputLengthException("output buffer too short");
            }
            return this._keyis128 ? processBlock128(bArr, i, bArr2, i2) : processBlock192or256(bArr, i, bArr2, i2);
        }
        throw new IllegalStateException("Camellia is not initialized");
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }
}