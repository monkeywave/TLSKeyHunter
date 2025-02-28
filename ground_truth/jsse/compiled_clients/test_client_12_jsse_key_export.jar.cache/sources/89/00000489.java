package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MaxBytesExceededException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/Salsa20Engine.class */
public class Salsa20Engine implements SkippingStreamCipher {
    public static final int DEFAULT_ROUNDS = 20;
    private static final int STATE_SIZE = 16;
    private static final int[] TAU_SIGMA = Pack.littleEndianToInt(Strings.toByteArray("expand 16-byte kexpand 32-byte k"), 0, 8);
    protected static final byte[] sigma = Strings.toByteArray("expand 32-byte k");
    protected static final byte[] tau = Strings.toByteArray("expand 16-byte k");
    protected int rounds;
    private int index;
    protected int[] engineState;

    /* renamed from: x */
    protected int[] f371x;
    private byte[] keyStream;
    private boolean initialised;
    private int cW0;
    private int cW1;
    private int cW2;

    /* JADX INFO: Access modifiers changed from: protected */
    public void packTauOrSigma(int i, int[] iArr, int i2) {
        int i3 = (i - 16) / 4;
        iArr[i2] = TAU_SIGMA[i3];
        iArr[i2 + 1] = TAU_SIGMA[i3 + 1];
        iArr[i2 + 2] = TAU_SIGMA[i3 + 2];
        iArr[i2 + 3] = TAU_SIGMA[i3 + 3];
    }

    public Salsa20Engine() {
        this(20);
    }

    public Salsa20Engine(int i) {
        this.index = 0;
        this.engineState = new int[16];
        this.f371x = new int[16];
        this.keyStream = new byte[64];
        this.initialised = false;
        if (i <= 0 || (i & 1) != 0) {
            throw new IllegalArgumentException("'rounds' must be a positive, even number");
        }
        this.rounds = i;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        if (iv == null || iv.length != getNonceSize()) {
            throw new IllegalArgumentException(getAlgorithmName() + " requires exactly " + getNonceSize() + " bytes of IV");
        }
        CipherParameters parameters = parametersWithIV.getParameters();
        if (parameters == null) {
            if (!this.initialised) {
                throw new IllegalStateException(getAlgorithmName() + " KeyParameter can not be null for first initialisation");
            }
            setKey(null, iv);
        } else if (!(parameters instanceof KeyParameter)) {
            throw new IllegalArgumentException(getAlgorithmName() + " Init parameters must contain a KeyParameter (or null for re-init)");
        } else {
            setKey(((KeyParameter) parameters).getKey(), iv);
        }
        reset();
        this.initialised = true;
    }

    protected int getNonceSize() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        String str;
        str = "Salsa20";
        return this.rounds != 20 ? str + "/" + this.rounds : "Salsa20";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        if (limitExceeded()) {
            throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
        }
        byte b2 = (byte) (this.keyStream[this.index] ^ b);
        this.index = (this.index + 1) & 63;
        if (this.index == 0) {
            advanceCounter();
            generateKeyStream(this.keyStream);
        }
        return b2;
    }

    protected void advanceCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i > 0) {
            int[] iArr = this.engineState;
            iArr[9] = iArr[9] + i;
        }
        int i3 = this.engineState[8];
        int[] iArr2 = this.engineState;
        iArr2[8] = iArr2[8] + i2;
        if (i3 == 0 || this.engineState[8] >= i3) {
            return;
        }
        int[] iArr3 = this.engineState;
        iArr3[9] = iArr3[9] + 1;
    }

    protected void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[8] + 1;
        iArr[8] = i;
        if (i == 0) {
            int[] iArr2 = this.engineState;
            iArr2[9] = iArr2[9] + 1;
        }
    }

    protected void retreatCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i != 0) {
            if ((this.engineState[9] & 4294967295L) < (i & 4294967295L)) {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
            int[] iArr = this.engineState;
            iArr[9] = iArr[9] - i;
        }
        if ((this.engineState[8] & 4294967295L) >= (i2 & 4294967295L)) {
            int[] iArr2 = this.engineState;
            iArr2[8] = iArr2[8] - i2;
        } else if (this.engineState[9] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        } else {
            int[] iArr3 = this.engineState;
            iArr3[9] = iArr3[9] - 1;
            int[] iArr4 = this.engineState;
            iArr4[8] = iArr4[8] - i2;
        }
    }

    protected void retreatCounter() {
        if (this.engineState[8] == 0 && this.engineState[9] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int[] iArr = this.engineState;
        int i = iArr[8] - 1;
        iArr[8] = i;
        if (i == -1) {
            int[] iArr2 = this.engineState;
            iArr2[9] = iArr2[9] - 1;
        }
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
            if (limitExceeded(i2)) {
                throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
            }
            for (int i4 = 0; i4 < i2; i4++) {
                bArr2[i4 + i3] = (byte) (this.keyStream[this.index] ^ bArr[i4 + i]);
                this.index = (this.index + 1) & 63;
                if (this.index == 0) {
                    advanceCounter();
                    generateKeyStream(this.keyStream);
                }
            }
            return i2;
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long skip(long j) {
        if (j < 0) {
            long j2 = -j;
            if (j2 >= 64) {
                long j3 = j2 / 64;
                retreatCounter(j3);
                j2 -= j3 * 64;
            }
            long j4 = 0;
            while (true) {
                long j5 = j4;
                if (j5 >= j2) {
                    break;
                }
                if (this.index == 0) {
                    retreatCounter();
                }
                this.index = (this.index - 1) & 63;
                j4 = j5 + 1;
            }
        } else {
            long j6 = j;
            if (j6 >= 64) {
                long j7 = j6 / 64;
                advanceCounter(j7);
                j6 -= j7 * 64;
            }
            int i = this.index;
            this.index = (this.index + ((int) j6)) & 63;
            if (this.index < i) {
                advanceCounter();
            }
        }
        generateKeyStream(this.keyStream);
        return j;
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long seekTo(long j) {
        reset();
        return skip(j);
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long getPosition() {
        return (getCounter() * 64) + this.index;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        this.index = 0;
        resetLimitCounter();
        resetCounter();
        generateKeyStream(this.keyStream);
    }

    protected long getCounter() {
        return (this.engineState[9] << 32) | (this.engineState[8] & 4294967295L);
    }

    protected void resetCounter() {
        int[] iArr = this.engineState;
        this.engineState[9] = 0;
        iArr[8] = 0;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setKey(byte[] bArr, byte[] bArr2) {
        if (bArr != null) {
            if (bArr.length != 16 && bArr.length != 32) {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }
            int length = (bArr.length - 16) / 4;
            this.engineState[0] = TAU_SIGMA[length];
            this.engineState[5] = TAU_SIGMA[length + 1];
            this.engineState[10] = TAU_SIGMA[length + 2];
            this.engineState[15] = TAU_SIGMA[length + 3];
            Pack.littleEndianToInt(bArr, 0, this.engineState, 1, 4);
            Pack.littleEndianToInt(bArr, bArr.length - 16, this.engineState, 11, 4);
        }
        Pack.littleEndianToInt(bArr2, 0, this.engineState, 6, 2);
    }

    protected void generateKeyStream(byte[] bArr) {
        salsaCore(this.rounds, this.engineState, this.f371x);
        Pack.intToLittleEndian(this.f371x, bArr, 0);
    }

    public static void salsaCore(int i, int[] iArr, int[] iArr2) {
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
            int rotateLeft = i6 ^ Integers.rotateLeft(i2 + i14, 7);
            int rotateLeft2 = i10 ^ Integers.rotateLeft(rotateLeft + i2, 9);
            int rotateLeft3 = i14 ^ Integers.rotateLeft(rotateLeft2 + rotateLeft, 13);
            int rotateLeft4 = i2 ^ Integers.rotateLeft(rotateLeft3 + rotateLeft2, 18);
            int rotateLeft5 = i11 ^ Integers.rotateLeft(i7 + i3, 7);
            int rotateLeft6 = i15 ^ Integers.rotateLeft(rotateLeft5 + i7, 9);
            int rotateLeft7 = i3 ^ Integers.rotateLeft(rotateLeft6 + rotateLeft5, 13);
            int rotateLeft8 = i7 ^ Integers.rotateLeft(rotateLeft7 + rotateLeft6, 18);
            int rotateLeft9 = i16 ^ Integers.rotateLeft(i12 + i8, 7);
            int rotateLeft10 = i4 ^ Integers.rotateLeft(rotateLeft9 + i12, 9);
            int rotateLeft11 = i8 ^ Integers.rotateLeft(rotateLeft10 + rotateLeft9, 13);
            int rotateLeft12 = i12 ^ Integers.rotateLeft(rotateLeft11 + rotateLeft10, 18);
            int rotateLeft13 = i5 ^ Integers.rotateLeft(i17 + i13, 7);
            int rotateLeft14 = i9 ^ Integers.rotateLeft(rotateLeft13 + i17, 9);
            int rotateLeft15 = i13 ^ Integers.rotateLeft(rotateLeft14 + rotateLeft13, 13);
            int rotateLeft16 = i17 ^ Integers.rotateLeft(rotateLeft15 + rotateLeft14, 18);
            i3 = rotateLeft7 ^ Integers.rotateLeft(rotateLeft4 + rotateLeft13, 7);
            i4 = rotateLeft10 ^ Integers.rotateLeft(i3 + rotateLeft4, 9);
            i5 = rotateLeft13 ^ Integers.rotateLeft(i4 + i3, 13);
            i2 = rotateLeft4 ^ Integers.rotateLeft(i5 + i4, 18);
            i8 = rotateLeft11 ^ Integers.rotateLeft(rotateLeft8 + rotateLeft, 7);
            i9 = rotateLeft14 ^ Integers.rotateLeft(i8 + rotateLeft8, 9);
            i6 = rotateLeft ^ Integers.rotateLeft(i9 + i8, 13);
            i7 = rotateLeft8 ^ Integers.rotateLeft(i6 + i9, 18);
            i13 = rotateLeft15 ^ Integers.rotateLeft(rotateLeft12 + rotateLeft5, 7);
            i10 = rotateLeft2 ^ Integers.rotateLeft(i13 + rotateLeft12, 9);
            i11 = rotateLeft5 ^ Integers.rotateLeft(i10 + i13, 13);
            i12 = rotateLeft12 ^ Integers.rotateLeft(i11 + i10, 18);
            i14 = rotateLeft3 ^ Integers.rotateLeft(rotateLeft16 + rotateLeft9, 7);
            i15 = rotateLeft6 ^ Integers.rotateLeft(i14 + rotateLeft16, 9);
            i16 = rotateLeft9 ^ Integers.rotateLeft(i15 + i14, 13);
            i17 = rotateLeft16 ^ Integers.rotateLeft(i16 + i15, 18);
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

    private void resetLimitCounter() {
        this.cW0 = 0;
        this.cW1 = 0;
        this.cW2 = 0;
    }

    private boolean limitExceeded() {
        int i = this.cW0 + 1;
        this.cW0 = i;
        if (i == 0) {
            int i2 = this.cW1 + 1;
            this.cW1 = i2;
            if (i2 == 0) {
                int i3 = this.cW2 + 1;
                this.cW2 = i3;
                return (i3 & 32) != 0;
            }
            return false;
        }
        return false;
    }

    private boolean limitExceeded(int i) {
        this.cW0 += i;
        if (this.cW0 >= i || this.cW0 < 0) {
            return false;
        }
        int i2 = this.cW1 + 1;
        this.cW1 = i2;
        if (i2 == 0) {
            int i3 = this.cW2 + 1;
            this.cW2 = i3;
            return (i3 & 32) != 0;
        }
        return false;
    }
}