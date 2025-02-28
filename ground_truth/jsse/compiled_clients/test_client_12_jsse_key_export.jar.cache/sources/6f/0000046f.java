package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ISAACEngine.class */
public class ISAACEngine implements StreamCipher {
    private final int sizeL = 8;
    private final int stateArraySize = 256;
    private int[] engineState = null;
    private int[] results = null;

    /* renamed from: a */
    private int f347a = 0;

    /* renamed from: b */
    private int f348b = 0;

    /* renamed from: c */
    private int f349c = 0;
    private int index = 0;
    private byte[] keyStream = new byte[1024];
    private byte[] workingKey = null;
    private boolean initialised = false;

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to ISAAC init - " + cipherParameters.getClass().getName());
        }
        setKey(((KeyParameter) cipherParameters).getKey());
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        if (this.index == 0) {
            isaac();
            this.keyStream = Pack.intToBigEndian(this.results);
        }
        byte b2 = (byte) (this.keyStream[this.index] ^ b);
        this.index = (this.index + 1) & 1023;
        return b2;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (this.initialised) {
            if (i + i2 > bArr.length) {
                throw new DataLengthException("input buffer too short");
            }
            if (i3 + i2 > bArr2.length) {
                throw new OutputLengthException("output buffer too short");
            }
            for (int i4 = 0; i4 < i2; i4++) {
                if (this.index == 0) {
                    isaac();
                    this.keyStream = Pack.intToBigEndian(this.results);
                }
                bArr2[i4 + i3] = (byte) (this.keyStream[this.index] ^ bArr[i4 + i]);
                this.index = (this.index + 1) & 1023;
            }
            return i2;
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "ISAAC";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        setKey(this.workingKey);
    }

    private void setKey(byte[] bArr) {
        this.workingKey = bArr;
        if (this.engineState == null) {
            this.engineState = new int[256];
        }
        if (this.results == null) {
            this.results = new int[256];
        }
        for (int i = 0; i < 256; i++) {
            this.results[i] = 0;
            this.engineState[i] = 0;
        }
        this.f349c = 0;
        this.f348b = 0;
        this.f347a = 0;
        this.index = 0;
        byte[] bArr2 = new byte[bArr.length + (bArr.length & 3)];
        System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
        for (int i2 = 0; i2 < bArr2.length; i2 += 4) {
            this.results[i2 >>> 2] = Pack.littleEndianToInt(bArr2, i2);
        }
        int[] iArr = new int[8];
        for (int i3 = 0; i3 < 8; i3++) {
            iArr[i3] = -1640531527;
        }
        for (int i4 = 0; i4 < 4; i4++) {
            mix(iArr);
        }
        int i5 = 0;
        while (i5 < 2) {
            for (int i6 = 0; i6 < 256; i6 += 8) {
                for (int i7 = 0; i7 < 8; i7++) {
                    int i8 = i7;
                    iArr[i8] = iArr[i8] + (i5 < 1 ? this.results[i6 + i7] : this.engineState[i6 + i7]);
                }
                mix(iArr);
                for (int i9 = 0; i9 < 8; i9++) {
                    this.engineState[i6 + i9] = iArr[i9];
                }
            }
            i5++;
        }
        isaac();
        this.initialised = true;
    }

    private void isaac() {
        int i = this.f348b;
        int i2 = this.f349c + 1;
        this.f349c = i2;
        this.f348b = i + i2;
        for (int i3 = 0; i3 < 256; i3++) {
            int i4 = this.engineState[i3];
            switch (i3 & 3) {
                case 0:
                    this.f347a ^= this.f347a << 13;
                    break;
                case 1:
                    this.f347a ^= this.f347a >>> 6;
                    break;
                case 2:
                    this.f347a ^= this.f347a << 2;
                    break;
                case 3:
                    this.f347a ^= this.f347a >>> 16;
                    break;
            }
            this.f347a += this.engineState[(i3 + 128) & GF2Field.MASK];
            int i5 = this.engineState[(i4 >>> 2) & GF2Field.MASK] + this.f347a + this.f348b;
            this.engineState[i3] = i5;
            int i6 = this.engineState[(i5 >>> 10) & GF2Field.MASK] + i4;
            this.f348b = i6;
            this.results[i3] = i6;
        }
    }

    private void mix(int[] iArr) {
        iArr[0] = iArr[0] ^ (iArr[1] << 11);
        iArr[3] = iArr[3] + iArr[0];
        iArr[1] = iArr[1] + iArr[2];
        iArr[1] = iArr[1] ^ (iArr[2] >>> 2);
        iArr[4] = iArr[4] + iArr[1];
        iArr[2] = iArr[2] + iArr[3];
        iArr[2] = iArr[2] ^ (iArr[3] << 8);
        iArr[5] = iArr[5] + iArr[2];
        iArr[3] = iArr[3] + iArr[4];
        iArr[3] = iArr[3] ^ (iArr[4] >>> 16);
        iArr[6] = iArr[6] + iArr[3];
        iArr[4] = iArr[4] + iArr[5];
        iArr[4] = iArr[4] ^ (iArr[5] << 10);
        iArr[7] = iArr[7] + iArr[4];
        iArr[5] = iArr[5] + iArr[6];
        iArr[5] = iArr[5] ^ (iArr[6] >>> 4);
        iArr[0] = iArr[0] + iArr[5];
        iArr[6] = iArr[6] + iArr[7];
        iArr[6] = iArr[6] ^ (iArr[7] << 8);
        iArr[1] = iArr[1] + iArr[6];
        iArr[7] = iArr[7] + iArr[0];
        iArr[7] = iArr[7] ^ (iArr[0] >>> 9);
        iArr[2] = iArr[2] + iArr[7];
        iArr[0] = iArr[0] + iArr[1];
    }
}