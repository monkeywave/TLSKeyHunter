package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ChaChaEngine.class */
public class ChaChaEngine extends Salsa20Engine {
    public ChaChaEngine() {
    }

    public ChaChaEngine(int i) {
        super(i);
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine, org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "ChaCha" + this.rounds;
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void advanceCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i > 0) {
            int[] iArr = this.engineState;
            iArr[13] = iArr[13] + i;
        }
        int i3 = this.engineState[12];
        int[] iArr2 = this.engineState;
        iArr2[12] = iArr2[12] + i2;
        if (i3 == 0 || this.engineState[12] >= i3) {
            return;
        }
        int[] iArr3 = this.engineState;
        iArr3[13] = iArr3[13] + 1;
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[12] + 1;
        iArr[12] = i;
        if (i == 0) {
            int[] iArr2 = this.engineState;
            iArr2[13] = iArr2[13] + 1;
        }
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void retreatCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i != 0) {
            if ((this.engineState[13] & 4294967295L) < (i & 4294967295L)) {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
            int[] iArr = this.engineState;
            iArr[13] = iArr[13] - i;
        }
        if ((this.engineState[12] & 4294967295L) >= (i2 & 4294967295L)) {
            int[] iArr2 = this.engineState;
            iArr2[12] = iArr2[12] - i2;
        } else if (this.engineState[13] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        } else {
            int[] iArr3 = this.engineState;
            iArr3[13] = iArr3[13] - 1;
            int[] iArr4 = this.engineState;
            iArr4[12] = iArr4[12] - i2;
        }
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void retreatCounter() {
        if (this.engineState[12] == 0 && this.engineState[13] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr = this.engineState;
        int i = iArr[12] - 1;
        iArr[12] = i;
        if (i == -1) {
            int[] iArr2 = this.engineState;
            iArr2[13] = iArr2[13] - 1;
        }
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected long getCounter() {
        return (this.engineState[13] << 32) | (this.engineState[12] & 4294967295L);
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void resetCounter() {
        int[] iArr = this.engineState;
        this.engineState[13] = 0;
        iArr[12] = 0;
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void setKey(byte[] bArr, byte[] bArr2) {
        if (bArr != null) {
            if (bArr.length != 16 && bArr.length != 32) {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }
            packTauOrSigma(bArr.length, this.engineState, 0);
            Pack.littleEndianToInt(bArr, 0, this.engineState, 4, 4);
            Pack.littleEndianToInt(bArr, bArr.length - 16, this.engineState, 8, 4);
        }
        Pack.littleEndianToInt(bArr2, 0, this.engineState, 14, 2);
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void generateKeyStream(byte[] bArr) {
        chachaCore(this.rounds, this.engineState, this.f371x);
        Pack.intToLittleEndian(this.f371x, bArr, 0);
    }

    public static void chachaCore(int i, int[] iArr, int[] iArr2) {
        if (iArr.length != 16) {
            throw new IllegalArgumentException();
        }
        if (iArr2.length != 16) {
            throw new IllegalArgumentException();
        }
        if (i % 2 != 0) {
            throw new IllegalArgumentException("Number of rounds must be even");
        }
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = iArr[7];
        int i10 = iArr[8];
        int i11 = iArr[9];
        int i12 = iArr[10];
        int i13 = iArr[11];
        int i14 = iArr[12];
        int i15 = iArr[13];
        int i16 = iArr[14];
        int i17 = iArr[15];
        for (int i18 = i; i18 > 0; i18 -= 2) {
            int i19 = i2 + i6;
            int rotateLeft = Integers.rotateLeft(i14 ^ i19, 16);
            int i20 = i10 + rotateLeft;
            int rotateLeft2 = Integers.rotateLeft(i6 ^ i20, 12);
            int i21 = i19 + rotateLeft2;
            int rotateLeft3 = Integers.rotateLeft(rotateLeft ^ i21, 8);
            int i22 = i20 + rotateLeft3;
            int rotateLeft4 = Integers.rotateLeft(rotateLeft2 ^ i22, 7);
            int i23 = i3 + i7;
            int rotateLeft5 = Integers.rotateLeft(i15 ^ i23, 16);
            int i24 = i11 + rotateLeft5;
            int rotateLeft6 = Integers.rotateLeft(i7 ^ i24, 12);
            int i25 = i23 + rotateLeft6;
            int rotateLeft7 = Integers.rotateLeft(rotateLeft5 ^ i25, 8);
            int i26 = i24 + rotateLeft7;
            int rotateLeft8 = Integers.rotateLeft(rotateLeft6 ^ i26, 7);
            int i27 = i4 + i8;
            int rotateLeft9 = Integers.rotateLeft(i16 ^ i27, 16);
            int i28 = i12 + rotateLeft9;
            int rotateLeft10 = Integers.rotateLeft(i8 ^ i28, 12);
            int i29 = i27 + rotateLeft10;
            int rotateLeft11 = Integers.rotateLeft(rotateLeft9 ^ i29, 8);
            int i30 = i28 + rotateLeft11;
            int rotateLeft12 = Integers.rotateLeft(rotateLeft10 ^ i30, 7);
            int i31 = i5 + i9;
            int rotateLeft13 = Integers.rotateLeft(i17 ^ i31, 16);
            int i32 = i13 + rotateLeft13;
            int rotateLeft14 = Integers.rotateLeft(i9 ^ i32, 12);
            int i33 = i31 + rotateLeft14;
            int rotateLeft15 = Integers.rotateLeft(rotateLeft13 ^ i33, 8);
            int i34 = i32 + rotateLeft15;
            int rotateLeft16 = Integers.rotateLeft(rotateLeft14 ^ i34, 7);
            int i35 = i21 + rotateLeft8;
            int rotateLeft17 = Integers.rotateLeft(rotateLeft15 ^ i35, 16);
            int i36 = i30 + rotateLeft17;
            int rotateLeft18 = Integers.rotateLeft(rotateLeft8 ^ i36, 12);
            i2 = i35 + rotateLeft18;
            i17 = Integers.rotateLeft(rotateLeft17 ^ i2, 8);
            i12 = i36 + i17;
            i7 = Integers.rotateLeft(rotateLeft18 ^ i12, 7);
            int i37 = i25 + rotateLeft12;
            int rotateLeft19 = Integers.rotateLeft(rotateLeft3 ^ i37, 16);
            int i38 = i34 + rotateLeft19;
            int rotateLeft20 = Integers.rotateLeft(rotateLeft12 ^ i38, 12);
            i3 = i37 + rotateLeft20;
            i14 = Integers.rotateLeft(rotateLeft19 ^ i3, 8);
            i13 = i38 + i14;
            i8 = Integers.rotateLeft(rotateLeft20 ^ i13, 7);
            int i39 = i29 + rotateLeft16;
            int rotateLeft21 = Integers.rotateLeft(rotateLeft7 ^ i39, 16);
            int i40 = i22 + rotateLeft21;
            int rotateLeft22 = Integers.rotateLeft(rotateLeft16 ^ i40, 12);
            i4 = i39 + rotateLeft22;
            i15 = Integers.rotateLeft(rotateLeft21 ^ i4, 8);
            i10 = i40 + i15;
            i9 = Integers.rotateLeft(rotateLeft22 ^ i10, 7);
            int i41 = i33 + rotateLeft4;
            int rotateLeft23 = Integers.rotateLeft(rotateLeft11 ^ i41, 16);
            int i42 = i26 + rotateLeft23;
            int rotateLeft24 = Integers.rotateLeft(rotateLeft4 ^ i42, 12);
            i5 = i41 + rotateLeft24;
            i16 = Integers.rotateLeft(rotateLeft23 ^ i5, 8);
            i11 = i42 + i16;
            i6 = Integers.rotateLeft(rotateLeft24 ^ i11, 7);
        }
        iArr2[0] = i2 + iArr[0];
        iArr2[1] = i3 + iArr[1];
        iArr2[2] = i4 + iArr[2];
        iArr2[3] = i5 + iArr[3];
        iArr2[4] = i6 + iArr[4];
        iArr2[5] = i7 + iArr[5];
        iArr2[6] = i8 + iArr[6];
        iArr2[7] = i9 + iArr[7];
        iArr2[8] = i10 + iArr[8];
        iArr2[9] = i11 + iArr[9];
        iArr2[10] = i12 + iArr[10];
        iArr2[11] = i13 + iArr[11];
        iArr2[12] = i14 + iArr[12];
        iArr2[13] = i15 + iArr[13];
        iArr2[14] = i16 + iArr[14];
        iArr2[15] = i17 + iArr[15];
    }
}