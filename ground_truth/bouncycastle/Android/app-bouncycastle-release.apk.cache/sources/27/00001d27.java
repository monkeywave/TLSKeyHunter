package org.bouncycastle.crypto.engines;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class ChaChaEngine extends Salsa20Engine {
    public ChaChaEngine() {
    }

    public ChaChaEngine(int i) {
        super(i);
    }

    public static void chachaCore(int i, int[] iArr, int[] iArr2) {
        int i2 = 16;
        if (iArr.length != 16) {
            throw new IllegalArgumentException();
        }
        if (iArr2.length != 16) {
            throw new IllegalArgumentException();
        }
        if (i % 2 != 0) {
            throw new IllegalArgumentException("Number of rounds must be even");
        }
        char c = 0;
        int i3 = iArr[0];
        int i4 = iArr[1];
        int i5 = iArr[2];
        int i6 = iArr[3];
        int i7 = iArr[4];
        int i8 = iArr[5];
        int i9 = iArr[6];
        int i10 = 7;
        int i11 = iArr[7];
        int i12 = 8;
        int i13 = iArr[8];
        int i14 = iArr[9];
        int i15 = iArr[10];
        int i16 = iArr[11];
        int i17 = 12;
        int i18 = iArr[12];
        int i19 = iArr[13];
        int i20 = iArr[14];
        int i21 = iArr[15];
        int i22 = i20;
        int i23 = i19;
        int i24 = i18;
        int i25 = i16;
        int i26 = i15;
        int i27 = i14;
        int i28 = i13;
        int i29 = i11;
        int i30 = i9;
        int i31 = i8;
        int i32 = i7;
        int i33 = i6;
        int i34 = i5;
        int i35 = i4;
        int i36 = i3;
        int i37 = i;
        while (i37 > 0) {
            int i38 = i36 + i32;
            int rotateLeft = Integers.rotateLeft(i24 ^ i38, i2);
            int i39 = i28 + rotateLeft;
            int rotateLeft2 = Integers.rotateLeft(i32 ^ i39, i17);
            int i40 = i38 + rotateLeft2;
            int rotateLeft3 = Integers.rotateLeft(rotateLeft ^ i40, i12);
            int i41 = i39 + rotateLeft3;
            int rotateLeft4 = Integers.rotateLeft(rotateLeft2 ^ i41, i10);
            int i42 = i35 + i31;
            int rotateLeft5 = Integers.rotateLeft(i23 ^ i42, i2);
            int i43 = i27 + rotateLeft5;
            int rotateLeft6 = Integers.rotateLeft(i31 ^ i43, i17);
            int i44 = i42 + rotateLeft6;
            int rotateLeft7 = Integers.rotateLeft(rotateLeft5 ^ i44, i12);
            int i45 = i43 + rotateLeft7;
            int rotateLeft8 = Integers.rotateLeft(rotateLeft6 ^ i45, i10);
            int i46 = i34 + i30;
            int rotateLeft9 = Integers.rotateLeft(i22 ^ i46, i2);
            int i47 = i26 + rotateLeft9;
            int rotateLeft10 = Integers.rotateLeft(i30 ^ i47, i17);
            int i48 = i46 + rotateLeft10;
            int rotateLeft11 = Integers.rotateLeft(rotateLeft9 ^ i48, i12);
            int i49 = i47 + rotateLeft11;
            int rotateLeft12 = Integers.rotateLeft(rotateLeft10 ^ i49, i10);
            int i50 = i33 + i29;
            int rotateLeft13 = Integers.rotateLeft(i21 ^ i50, 16);
            int i51 = i25 + rotateLeft13;
            int rotateLeft14 = Integers.rotateLeft(i29 ^ i51, i17);
            int i52 = i50 + rotateLeft14;
            int rotateLeft15 = Integers.rotateLeft(rotateLeft13 ^ i52, 8);
            int i53 = i51 + rotateLeft15;
            int rotateLeft16 = Integers.rotateLeft(rotateLeft14 ^ i53, 7);
            int i54 = i40 + rotateLeft8;
            int rotateLeft17 = Integers.rotateLeft(rotateLeft15 ^ i54, 16);
            int i55 = i49 + rotateLeft17;
            int rotateLeft18 = Integers.rotateLeft(rotateLeft8 ^ i55, 12);
            i36 = i54 + rotateLeft18;
            i21 = Integers.rotateLeft(rotateLeft17 ^ i36, 8);
            i26 = i55 + i21;
            i31 = Integers.rotateLeft(rotateLeft18 ^ i26, 7);
            int i56 = i44 + rotateLeft12;
            int rotateLeft19 = Integers.rotateLeft(rotateLeft3 ^ i56, 16);
            int i57 = i53 + rotateLeft19;
            int rotateLeft20 = Integers.rotateLeft(rotateLeft12 ^ i57, 12);
            i35 = i56 + rotateLeft20;
            i24 = Integers.rotateLeft(rotateLeft19 ^ i35, 8);
            i25 = i57 + i24;
            i30 = Integers.rotateLeft(rotateLeft20 ^ i25, 7);
            int i58 = i48 + rotateLeft16;
            int rotateLeft21 = Integers.rotateLeft(rotateLeft7 ^ i58, 16);
            int i59 = i41 + rotateLeft21;
            int rotateLeft22 = Integers.rotateLeft(rotateLeft16 ^ i59, 12);
            i34 = i58 + rotateLeft22;
            i23 = Integers.rotateLeft(rotateLeft21 ^ i34, 8);
            i28 = i59 + i23;
            i29 = Integers.rotateLeft(rotateLeft22 ^ i28, 7);
            int i60 = i52 + rotateLeft4;
            i2 = 16;
            int rotateLeft23 = Integers.rotateLeft(rotateLeft11 ^ i60, 16);
            int i61 = i45 + rotateLeft23;
            int rotateLeft24 = Integers.rotateLeft(rotateLeft4 ^ i61, 12);
            i33 = i60 + rotateLeft24;
            i22 = Integers.rotateLeft(rotateLeft23 ^ i33, 8);
            i27 = i61 + i22;
            i32 = Integers.rotateLeft(rotateLeft24 ^ i27, 7);
            i37 -= 2;
            c = 0;
            i17 = 12;
            i12 = 8;
            i10 = 7;
        }
        iArr2[c] = i36 + iArr[c];
        iArr2[1] = i35 + iArr[1];
        iArr2[2] = i34 + iArr[2];
        iArr2[3] = i33 + iArr[3];
        iArr2[4] = i32 + iArr[4];
        iArr2[5] = i31 + iArr[5];
        iArr2[6] = i30 + iArr[6];
        iArr2[7] = i29 + iArr[7];
        iArr2[8] = i28 + iArr[8];
        iArr2[9] = i27 + iArr[9];
        iArr2[10] = i26 + iArr[10];
        iArr2[11] = i25 + iArr[11];
        iArr2[12] = i24 + iArr[12];
        iArr2[13] = i23 + iArr[13];
        iArr2[14] = i22 + iArr[14];
        iArr2[15] = i21 + iArr[15];
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
    protected void generateKeyStream(byte[] bArr) {
        chachaCore(this.rounds, this.engineState, this.f687x);
        Pack.intToLittleEndian(this.f687x, bArr, 0);
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine, org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "ChaCha" + this.rounds;
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected long getCounter() {
        return (this.engineState[13] << 32) | (this.engineState[12] & BodyPartID.bodyIdMax);
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void resetCounter() {
        int[] iArr = this.engineState;
        this.engineState[13] = 0;
        iArr[12] = 0;
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void retreatCounter() {
        int[] iArr;
        if (this.engineState[12] == 0 && this.engineState[13] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr2 = this.engineState;
        int i = iArr2[12] - 1;
        iArr2[12] = i;
        if (i == -1) {
            this.engineState[13] = iArr[13] - 1;
        }
    }

    @Override // org.bouncycastle.crypto.engines.Salsa20Engine
    protected void retreatCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i != 0) {
            if ((this.engineState[13] & BodyPartID.bodyIdMax) < (i & BodyPartID.bodyIdMax)) {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
            int[] iArr = this.engineState;
            iArr[13] = iArr[13] - i;
        }
        if ((this.engineState[12] & BodyPartID.bodyIdMax) >= (BodyPartID.bodyIdMax & i2)) {
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
}