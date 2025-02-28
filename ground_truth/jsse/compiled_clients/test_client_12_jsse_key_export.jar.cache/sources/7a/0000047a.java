package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC6Engine.class */
public class RC6Engine implements BlockCipher {
    private static final int wordSize = 32;
    private static final int bytesPerWord = 4;
    private static final int _noRounds = 20;

    /* renamed from: _S */
    private int[] f357_S = null;
    private static final int P32 = -1209970333;
    private static final int Q32 = -1640531527;
    private static final int LGW = 5;
    private boolean forEncryption;

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "RC6";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to RC6 init - " + cipherParameters.getClass().getName());
        }
        this.forEncryption = z;
        setKey(((KeyParameter) cipherParameters).getKey());
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int blockSize = getBlockSize();
        if (this.f357_S == null) {
            throw new IllegalStateException("RC6 engine not initialised");
        }
        if (i + blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + blockSize > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        return this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    private void setKey(byte[] bArr) {
        if ((bArr.length + 3) / 4 == 0) {
        }
        int[] iArr = new int[((bArr.length + 4) - 1) / 4];
        for (int length = bArr.length - 1; length >= 0; length--) {
            iArr[length / 4] = (iArr[length / 4] << 8) + (bArr[length] & 255);
        }
        this.f357_S = new int[44];
        this.f357_S[0] = P32;
        for (int i = 1; i < this.f357_S.length; i++) {
            this.f357_S[i] = this.f357_S[i - 1] + Q32;
        }
        int length2 = iArr.length > this.f357_S.length ? 3 * iArr.length : 3 * this.f357_S.length;
        int i2 = 0;
        int i3 = 0;
        int i4 = 0;
        int i5 = 0;
        for (int i6 = 0; i6 < length2; i6++) {
            int rotateLeft = rotateLeft(this.f357_S[i4] + i2 + i3, 3);
            this.f357_S[i4] = rotateLeft;
            i2 = rotateLeft;
            int rotateLeft2 = rotateLeft(iArr[i5] + i2 + i3, i2 + i3);
            iArr[i5] = rotateLeft2;
            i3 = rotateLeft2;
            i4 = (i4 + 1) % this.f357_S.length;
            i5 = (i5 + 1) % iArr.length;
        }
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToWord = bytesToWord(bArr, i);
        int bytesToWord2 = bytesToWord(bArr, i + 4);
        int bytesToWord3 = bytesToWord(bArr, i + 8);
        int bytesToWord4 = bytesToWord(bArr, i + 12);
        int i3 = bytesToWord2 + this.f357_S[0];
        int i4 = bytesToWord4 + this.f357_S[1];
        for (int i5 = 1; i5 <= 20; i5++) {
            int rotateLeft = rotateLeft(i3 * ((2 * i3) + 1), 5);
            int rotateLeft2 = rotateLeft(i4 * ((2 * i4) + 1), 5);
            int rotateLeft3 = rotateLeft(bytesToWord ^ rotateLeft, rotateLeft2) + this.f357_S[2 * i5];
            bytesToWord = i3;
            i3 = rotateLeft(bytesToWord3 ^ rotateLeft2, rotateLeft) + this.f357_S[(2 * i5) + 1];
            bytesToWord3 = i4;
            i4 = rotateLeft3;
        }
        int i6 = bytesToWord + this.f357_S[42];
        int i7 = bytesToWord3 + this.f357_S[43];
        wordToBytes(i6, bArr2, i2);
        wordToBytes(i3, bArr2, i2 + 4);
        wordToBytes(i7, bArr2, i2 + 8);
        wordToBytes(i4, bArr2, i2 + 12);
        return 16;
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToWord = bytesToWord(bArr, i);
        int bytesToWord2 = bytesToWord(bArr, i + 4);
        int bytesToWord3 = bytesToWord(bArr, i + 8);
        int bytesToWord4 = bytesToWord(bArr, i + 12);
        int i3 = bytesToWord3 - this.f357_S[43];
        int i4 = bytesToWord - this.f357_S[42];
        for (int i5 = 20; i5 >= 1; i5--) {
            int i6 = bytesToWord4;
            bytesToWord4 = i3;
            int i7 = bytesToWord2;
            bytesToWord2 = i4;
            int rotateLeft = rotateLeft(bytesToWord2 * ((2 * bytesToWord2) + 1), 5);
            int rotateLeft2 = rotateLeft(bytesToWord4 * ((2 * bytesToWord4) + 1), 5);
            i3 = rotateRight(i7 - this.f357_S[(2 * i5) + 1], rotateLeft) ^ rotateLeft2;
            i4 = rotateRight(i6 - this.f357_S[2 * i5], rotateLeft2) ^ rotateLeft;
        }
        int i8 = bytesToWord4 - this.f357_S[1];
        int i9 = bytesToWord2 - this.f357_S[0];
        wordToBytes(i4, bArr2, i2);
        wordToBytes(i9, bArr2, i2 + 4);
        wordToBytes(i3, bArr2, i2 + 8);
        wordToBytes(i8, bArr2, i2 + 12);
        return 16;
    }

    private int rotateLeft(int i, int i2) {
        return (i << i2) | (i >>> (-i2));
    }

    private int rotateRight(int i, int i2) {
        return (i >>> i2) | (i << (-i2));
    }

    private int bytesToWord(byte[] bArr, int i) {
        int i2 = 0;
        for (int i3 = 3; i3 >= 0; i3--) {
            i2 = (i2 << 8) + (bArr[i3 + i] & 255);
        }
        return i2;
    }

    private void wordToBytes(int i, byte[] bArr, int i2) {
        for (int i3 = 0; i3 < 4; i3++) {
            bArr[i3 + i2] = (byte) i;
            i >>>= 8;
        }
    }
}