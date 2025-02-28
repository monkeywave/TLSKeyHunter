package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.RC5Parameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC532Engine.class */
public class RC532Engine implements BlockCipher {
    private int _noRounds = 12;

    /* renamed from: _S */
    private int[] f355_S = null;
    private static final int P32 = -1209970333;
    private static final int Q32 = -1640531527;
    private boolean forEncryption;

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "RC5-32";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (cipherParameters instanceof RC5Parameters) {
            RC5Parameters rC5Parameters = (RC5Parameters) cipherParameters;
            this._noRounds = rC5Parameters.getRounds();
            setKey(rC5Parameters.getKey());
        } else if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to RC532 init - " + cipherParameters.getClass().getName());
        } else {
            setKey(((KeyParameter) cipherParameters).getKey());
        }
        this.forEncryption = z;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        return this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    private void setKey(byte[] bArr) {
        int[] iArr = new int[(bArr.length + 3) / 4];
        for (int i = 0; i != bArr.length; i++) {
            int i2 = i / 4;
            iArr[i2] = iArr[i2] + ((bArr[i] & 255) << (8 * (i % 4)));
        }
        this.f355_S = new int[2 * (this._noRounds + 1)];
        this.f355_S[0] = P32;
        for (int i3 = 1; i3 < this.f355_S.length; i3++) {
            this.f355_S[i3] = this.f355_S[i3 - 1] + Q32;
        }
        int length = iArr.length > this.f355_S.length ? 3 * iArr.length : 3 * this.f355_S.length;
        int i4 = 0;
        int i5 = 0;
        int i6 = 0;
        int i7 = 0;
        for (int i8 = 0; i8 < length; i8++) {
            int rotateLeft = rotateLeft(this.f355_S[i6] + i4 + i5, 3);
            this.f355_S[i6] = rotateLeft;
            i4 = rotateLeft;
            int rotateLeft2 = rotateLeft(iArr[i7] + i4 + i5, i4 + i5);
            iArr[i7] = rotateLeft2;
            i5 = rotateLeft2;
            i6 = (i6 + 1) % this.f355_S.length;
            i7 = (i7 + 1) % iArr.length;
        }
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToWord = bytesToWord(bArr, i) + this.f355_S[0];
        int bytesToWord2 = bytesToWord(bArr, i + 4) + this.f355_S[1];
        for (int i3 = 1; i3 <= this._noRounds; i3++) {
            bytesToWord = rotateLeft(bytesToWord ^ bytesToWord2, bytesToWord2) + this.f355_S[2 * i3];
            bytesToWord2 = rotateLeft(bytesToWord2 ^ bytesToWord, bytesToWord) + this.f355_S[(2 * i3) + 1];
        }
        wordToBytes(bytesToWord, bArr2, i2);
        wordToBytes(bytesToWord2, bArr2, i2 + 4);
        return 8;
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToWord = bytesToWord(bArr, i);
        int bytesToWord2 = bytesToWord(bArr, i + 4);
        for (int i3 = this._noRounds; i3 >= 1; i3--) {
            bytesToWord2 = rotateRight(bytesToWord2 - this.f355_S[(2 * i3) + 1], bytesToWord) ^ bytesToWord;
            bytesToWord = rotateRight(bytesToWord - this.f355_S[2 * i3], bytesToWord2) ^ bytesToWord2;
        }
        wordToBytes(bytesToWord - this.f355_S[0], bArr2, i2);
        wordToBytes(bytesToWord2 - this.f355_S[1], bArr2, i2 + 4);
        return 8;
    }

    private int rotateLeft(int i, int i2) {
        return (i << (i2 & 31)) | (i >>> (32 - (i2 & 31)));
    }

    private int rotateRight(int i, int i2) {
        return (i >>> (i2 & 31)) | (i << (32 - (i2 & 31)));
    }

    private int bytesToWord(byte[] bArr, int i) {
        return (bArr[i] & 255) | ((bArr[i + 1] & 255) << 8) | ((bArr[i + 2] & 255) << 16) | ((bArr[i + 3] & 255) << 24);
    }

    private void wordToBytes(int i, byte[] bArr, int i2) {
        bArr[i2] = (byte) i;
        bArr[i2 + 1] = (byte) (i >> 8);
        bArr[i2 + 2] = (byte) (i >> 16);
        bArr[i2 + 3] = (byte) (i >> 24);
    }
}