package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/NoekeonEngine.class */
public class NoekeonEngine implements BlockCipher {
    private static final int SIZE = 16;
    private static final byte[] roundConstants = {Byte.MIN_VALUE, 27, 54, 108, -40, -85, 77, -102, 47, 94, -68, 99, -58, -105, 53, 106, -44};

    /* renamed from: k */
    private final int[] f350k = new int[4];
    private boolean _initialised = false;
    private boolean _forEncryption;

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return "Noekeon";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to Noekeon init - " + cipherParameters.getClass().getName());
        }
        byte[] key = ((KeyParameter) cipherParameters).getKey();
        if (key.length != 16) {
            throw new IllegalArgumentException("Key length not 128 bits.");
        }
        Pack.bigEndianToInt(key, 0, this.f350k, 0, 4);
        if (!z) {
            int i = this.f350k[0];
            int i2 = this.f350k[1];
            int i3 = this.f350k[2];
            int i4 = this.f350k[3];
            int i5 = i ^ i3;
            int rotateLeft = i5 ^ (Integers.rotateLeft(i5, 8) ^ Integers.rotateLeft(i5, 24));
            int i6 = i2 ^ i4;
            int rotateLeft2 = i6 ^ (Integers.rotateLeft(i6, 8) ^ Integers.rotateLeft(i6, 24));
            int i7 = i ^ rotateLeft2;
            int i8 = i2 ^ rotateLeft;
            int i9 = i3 ^ rotateLeft2;
            this.f350k[0] = i7;
            this.f350k[1] = i8;
            this.f350k[2] = i9;
            this.f350k[3] = i4 ^ rotateLeft;
        }
        this._forEncryption = z;
        this._initialised = true;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this._initialised) {
            if (i > bArr.length - 16) {
                throw new DataLengthException("input buffer too short");
            }
            if (i2 > bArr2.length - 16) {
                throw new OutputLengthException("output buffer too short");
            }
            return this._forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, i);
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i + 4);
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, i + 8);
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i + 12);
        int i3 = this.f350k[0];
        int i4 = this.f350k[1];
        int i5 = this.f350k[2];
        int i6 = this.f350k[3];
        int i7 = 0;
        while (true) {
            int i8 = bigEndianToInt ^ (roundConstants[i7] & 255);
            int i9 = i8 ^ bigEndianToInt3;
            int rotateLeft = i9 ^ (Integers.rotateLeft(i9, 8) ^ Integers.rotateLeft(i9, 24));
            int i10 = i8 ^ i3;
            int i11 = bigEndianToInt2 ^ i4;
            int i12 = bigEndianToInt3 ^ i5;
            int i13 = bigEndianToInt4 ^ i6;
            int i14 = i11 ^ i13;
            int rotateLeft2 = i14 ^ (Integers.rotateLeft(i14, 8) ^ Integers.rotateLeft(i14, 24));
            int i15 = i10 ^ rotateLeft2;
            int i16 = i11 ^ rotateLeft;
            int i17 = i12 ^ rotateLeft2;
            int i18 = i13 ^ rotateLeft;
            i7++;
            if (i7 > 16) {
                Pack.intToBigEndian(i15, bArr2, i2);
                Pack.intToBigEndian(i16, bArr2, i2 + 4);
                Pack.intToBigEndian(i17, bArr2, i2 + 8);
                Pack.intToBigEndian(i18, bArr2, i2 + 12);
                return 16;
            }
            int rotateLeft3 = Integers.rotateLeft(i16, 1);
            int rotateLeft4 = Integers.rotateLeft(i17, 5);
            int rotateLeft5 = Integers.rotateLeft(i18, 2);
            int i19 = rotateLeft3 ^ (rotateLeft5 | rotateLeft4);
            int i20 = i15 ^ (rotateLeft4 & (i19 ^ (-1)));
            int i21 = ((rotateLeft5 ^ (i19 ^ (-1))) ^ rotateLeft4) ^ i20;
            int i22 = i19 ^ (i20 | i21);
            bigEndianToInt = rotateLeft5 ^ (i21 & i22);
            bigEndianToInt2 = Integers.rotateLeft(i22, 31);
            bigEndianToInt3 = Integers.rotateLeft(i21, 27);
            bigEndianToInt4 = Integers.rotateLeft(i20, 30);
        }
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, i);
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i + 4);
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, i + 8);
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i + 12);
        int i3 = this.f350k[0];
        int i4 = this.f350k[1];
        int i5 = this.f350k[2];
        int i6 = this.f350k[3];
        int i7 = 16;
        while (true) {
            int i8 = bigEndianToInt ^ bigEndianToInt3;
            int rotateLeft = i8 ^ (Integers.rotateLeft(i8, 8) ^ Integers.rotateLeft(i8, 24));
            int i9 = bigEndianToInt ^ i3;
            int i10 = bigEndianToInt2 ^ i4;
            int i11 = bigEndianToInt3 ^ i5;
            int i12 = bigEndianToInt4 ^ i6;
            int i13 = i10 ^ i12;
            int rotateLeft2 = i13 ^ (Integers.rotateLeft(i13, 8) ^ Integers.rotateLeft(i13, 24));
            int i14 = i9 ^ rotateLeft2;
            int i15 = i10 ^ rotateLeft;
            int i16 = i11 ^ rotateLeft2;
            int i17 = i12 ^ rotateLeft;
            int i18 = i14 ^ (roundConstants[i7] & 255);
            i7--;
            if (i7 < 0) {
                Pack.intToBigEndian(i18, bArr2, i2);
                Pack.intToBigEndian(i15, bArr2, i2 + 4);
                Pack.intToBigEndian(i16, bArr2, i2 + 8);
                Pack.intToBigEndian(i17, bArr2, i2 + 12);
                return 16;
            }
            int rotateLeft3 = Integers.rotateLeft(i15, 1);
            int rotateLeft4 = Integers.rotateLeft(i16, 5);
            int rotateLeft5 = Integers.rotateLeft(i17, 2);
            int i19 = rotateLeft3 ^ (rotateLeft5 | rotateLeft4);
            int i20 = i18 ^ (rotateLeft4 & (i19 ^ (-1)));
            int i21 = ((rotateLeft5 ^ (i19 ^ (-1))) ^ rotateLeft4) ^ i20;
            int i22 = i19 ^ (i20 | i21);
            bigEndianToInt = rotateLeft5 ^ (i21 & i22);
            bigEndianToInt2 = Integers.rotateLeft(i22, 31);
            bigEndianToInt3 = Integers.rotateLeft(i21, 27);
            bigEndianToInt4 = Integers.rotateLeft(i20, 30);
        }
    }
}