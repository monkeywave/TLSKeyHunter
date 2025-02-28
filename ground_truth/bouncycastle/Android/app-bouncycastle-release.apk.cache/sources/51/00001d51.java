package org.bouncycastle.crypto.engines;

import kotlin.UByte;
import kotlin.jvm.internal.ByteCompanionObject;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class NoekeonEngine implements BlockCipher {
    private static final int SIZE = 16;
    private static final byte[] roundConstants = {ByteCompanionObject.MIN_VALUE, 27, 54, 108, -40, -85, 77, -102, 47, 94, PSSSigner.TRAILER_IMPLICIT, 99, -58, -105, 53, 106, -44};
    private boolean _forEncryption;

    /* renamed from: k */
    private final int[] f656k = new int[4];
    private boolean _initialised = false;

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, i);
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i + 4);
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, i + 8);
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i + 12);
        int[] iArr = this.f656k;
        int i3 = iArr[0];
        int i4 = iArr[1];
        int i5 = iArr[2];
        int i6 = iArr[3];
        int i7 = 16;
        while (true) {
            int i8 = bigEndianToInt ^ bigEndianToInt3;
            int rotateLeft = i8 ^ (Integers.rotateLeft(i8, 8) ^ Integers.rotateLeft(i8, 24));
            int i9 = bigEndianToInt2 ^ i4;
            int i10 = bigEndianToInt4 ^ i6;
            int i11 = i9 ^ i10;
            int rotateLeft2 = (Integers.rotateLeft(i11, 24) ^ Integers.rotateLeft(i11, 8)) ^ i11;
            int i12 = i9 ^ rotateLeft;
            int i13 = (bigEndianToInt3 ^ i5) ^ rotateLeft2;
            int i14 = i10 ^ rotateLeft;
            int i15 = ((bigEndianToInt ^ i3) ^ rotateLeft2) ^ (roundConstants[i7] & UByte.MAX_VALUE);
            i7--;
            if (i7 < 0) {
                Pack.intToBigEndian(i15, bArr2, i2);
                Pack.intToBigEndian(i12, bArr2, i2 + 4);
                Pack.intToBigEndian(i13, bArr2, i2 + 8);
                Pack.intToBigEndian(i14, bArr2, i2 + 12);
                return 16;
            }
            int rotateLeft3 = Integers.rotateLeft(i12, 1);
            int rotateLeft4 = Integers.rotateLeft(i13, 5);
            int rotateLeft5 = Integers.rotateLeft(i14, 2);
            int i16 = rotateLeft3 ^ (rotateLeft5 | rotateLeft4);
            int i17 = ~i16;
            int i18 = i15 ^ (rotateLeft4 & i17);
            int i19 = (rotateLeft4 ^ (i17 ^ rotateLeft5)) ^ i18;
            int i20 = i16 ^ (i18 | i19);
            bigEndianToInt2 = Integers.rotateLeft(i20, 31);
            bigEndianToInt3 = Integers.rotateLeft(i19, 27);
            int rotateLeft6 = Integers.rotateLeft(i18, 30);
            bigEndianToInt = rotateLeft5 ^ (i19 & i20);
            bigEndianToInt4 = rotateLeft6;
        }
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        int bigEndianToInt = Pack.bigEndianToInt(bArr, i);
        int bigEndianToInt2 = Pack.bigEndianToInt(bArr, i + 4);
        int bigEndianToInt3 = Pack.bigEndianToInt(bArr, i + 8);
        int bigEndianToInt4 = Pack.bigEndianToInt(bArr, i + 12);
        int[] iArr = this.f656k;
        int i3 = 0;
        int i4 = iArr[0];
        int i5 = iArr[1];
        int i6 = iArr[2];
        int i7 = iArr[3];
        while (true) {
            int i8 = bigEndianToInt ^ (roundConstants[i3] & UByte.MAX_VALUE);
            int i9 = i8 ^ bigEndianToInt3;
            int rotateLeft = i9 ^ (Integers.rotateLeft(i9, 8) ^ Integers.rotateLeft(i9, 24));
            int i10 = bigEndianToInt2 ^ i5;
            int i11 = bigEndianToInt4 ^ i7;
            int i12 = i10 ^ i11;
            int rotateLeft2 = i12 ^ (Integers.rotateLeft(i12, 24) ^ Integers.rotateLeft(i12, 8));
            int i13 = (i8 ^ i4) ^ rotateLeft2;
            int i14 = i10 ^ rotateLeft;
            int i15 = (bigEndianToInt3 ^ i6) ^ rotateLeft2;
            int i16 = i11 ^ rotateLeft;
            i3++;
            if (i3 > 16) {
                Pack.intToBigEndian(i13, bArr2, i2);
                Pack.intToBigEndian(i14, bArr2, i2 + 4);
                Pack.intToBigEndian(i15, bArr2, i2 + 8);
                Pack.intToBigEndian(i16, bArr2, i2 + 12);
                return 16;
            }
            int rotateLeft3 = Integers.rotateLeft(i14, 1);
            int rotateLeft4 = Integers.rotateLeft(i15, 5);
            int rotateLeft5 = Integers.rotateLeft(i16, 2);
            int i17 = rotateLeft3 ^ (rotateLeft5 | rotateLeft4);
            int i18 = ~i17;
            int i19 = i13 ^ (rotateLeft4 & i18);
            int i20 = (rotateLeft4 ^ (i18 ^ rotateLeft5)) ^ i19;
            int i21 = i17 ^ (i19 | i20);
            bigEndianToInt2 = Integers.rotateLeft(i21, 31);
            bigEndianToInt3 = Integers.rotateLeft(i20, 27);
            int rotateLeft6 = Integers.rotateLeft(i19, 30);
            bigEndianToInt = rotateLeft5 ^ (i20 & i21);
            bigEndianToInt4 = rotateLeft6;
        }
    }

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
        Pack.bigEndianToInt(key, 0, this.f656k, 0, 4);
        if (!z) {
            int[] iArr = this.f656k;
            int i = iArr[0];
            int i2 = iArr[1];
            int i3 = iArr[2];
            int i4 = iArr[3];
            int i5 = i ^ i3;
            int rotateLeft = i5 ^ (Integers.rotateLeft(i5, 8) ^ Integers.rotateLeft(i5, 24));
            int i6 = i2 ^ i4;
            int rotateLeft2 = (Integers.rotateLeft(i6, 8) ^ Integers.rotateLeft(i6, 24)) ^ i6;
            int i7 = i2 ^ rotateLeft;
            int i8 = i4 ^ rotateLeft;
            int[] iArr2 = this.f656k;
            iArr2[0] = i ^ rotateLeft2;
            iArr2[1] = i7;
            iArr2[2] = i3 ^ rotateLeft2;
            iArr2[3] = i8;
        }
        this._forEncryption = z;
        this._initialised = true;
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), 128, cipherParameters, Utils.getPurpose(z)));
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) {
        if (this._initialised) {
            if (i <= bArr.length - 16) {
                if (i2 <= bArr2.length - 16) {
                    return this._forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
                }
                throw new OutputLengthException("output buffer too short");
            }
            throw new DataLengthException("input buffer too short");
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
    }
}