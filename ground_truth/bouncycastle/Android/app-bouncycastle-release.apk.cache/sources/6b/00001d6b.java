package org.bouncycastle.crypto.engines;

import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.MaxBytesExceededException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class Salsa20Engine implements SkippingStreamCipher {
    public static final int DEFAULT_ROUNDS = 20;
    private static final int STATE_SIZE = 16;
    private static final int[] TAU_SIGMA = Pack.littleEndianToInt(Strings.toByteArray("expand 16-byte kexpand 32-byte k"), 0, 8);
    protected static final byte[] sigma = Strings.toByteArray("expand 32-byte k");
    protected static final byte[] tau = Strings.toByteArray("expand 16-byte k");
    private int cW0;
    private int cW1;
    private int cW2;
    protected int[] engineState;
    private int index;
    private boolean initialised;
    private byte[] keyStream;
    protected int rounds;

    /* renamed from: x */
    protected int[] f687x;

    public Salsa20Engine() {
        this(20);
    }

    public Salsa20Engine(int i) {
        this.index = 0;
        this.engineState = new int[16];
        this.f687x = new int[16];
        this.keyStream = new byte[64];
        this.initialised = false;
        if (i <= 0 || (i & 1) != 0) {
            throw new IllegalArgumentException("'rounds' must be a positive, even number");
        }
        this.rounds = i;
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
        }
        return false;
    }

    private boolean limitExceeded(int i) {
        int i2 = this.cW0 + i;
        this.cW0 = i2;
        if (i2 >= i || i2 < 0) {
            return false;
        }
        int i3 = this.cW1 + 1;
        this.cW1 = i3;
        if (i3 == 0) {
            int i4 = this.cW2 + 1;
            this.cW2 = i4;
            return (i4 & 32) != 0;
        }
        return false;
    }

    private void resetLimitCounter() {
        this.cW0 = 0;
        this.cW1 = 0;
        this.cW2 = 0;
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
        char c = 0;
        int i2 = iArr[0];
        int i3 = iArr[1];
        int i4 = iArr[2];
        int i5 = iArr[3];
        int i6 = iArr[4];
        int i7 = iArr[5];
        int i8 = iArr[6];
        int i9 = 7;
        int i10 = iArr[7];
        int i11 = iArr[8];
        int i12 = 9;
        int i13 = iArr[9];
        int i14 = iArr[10];
        int i15 = iArr[11];
        int i16 = iArr[12];
        int i17 = 13;
        int i18 = iArr[13];
        int i19 = iArr[14];
        int i20 = iArr[15];
        int i21 = i19;
        int i22 = i18;
        int i23 = i16;
        int i24 = i15;
        int i25 = i14;
        int i26 = i13;
        int i27 = i11;
        int i28 = i10;
        int i29 = i8;
        int i30 = i7;
        int i31 = i6;
        int i32 = i5;
        int i33 = i4;
        int i34 = i3;
        int i35 = i2;
        int i36 = i;
        while (i36 > 0) {
            int rotateLeft = Integers.rotateLeft(i35 + i23, i9) ^ i31;
            int rotateLeft2 = i27 ^ Integers.rotateLeft(rotateLeft + i35, i12);
            int rotateLeft3 = i23 ^ Integers.rotateLeft(rotateLeft2 + rotateLeft, i17);
            int rotateLeft4 = Integers.rotateLeft(rotateLeft3 + rotateLeft2, 18) ^ i35;
            int rotateLeft5 = i26 ^ Integers.rotateLeft(i30 + i34, i9);
            int rotateLeft6 = i22 ^ Integers.rotateLeft(rotateLeft5 + i30, i12);
            int rotateLeft7 = i34 ^ Integers.rotateLeft(rotateLeft6 + rotateLeft5, i17);
            int rotateLeft8 = Integers.rotateLeft(rotateLeft7 + rotateLeft6, 18) ^ i30;
            int rotateLeft9 = i21 ^ Integers.rotateLeft(i25 + i29, 7);
            int rotateLeft10 = i33 ^ Integers.rotateLeft(rotateLeft9 + i25, 9);
            int rotateLeft11 = i29 ^ Integers.rotateLeft(rotateLeft10 + rotateLeft9, 13);
            int rotateLeft12 = i25 ^ Integers.rotateLeft(rotateLeft11 + rotateLeft10, 18);
            int rotateLeft13 = i32 ^ Integers.rotateLeft(i20 + i24, 7);
            int rotateLeft14 = i28 ^ Integers.rotateLeft(rotateLeft13 + i20, 9);
            int i37 = i36;
            int rotateLeft15 = i24 ^ Integers.rotateLeft(rotateLeft14 + rotateLeft13, 13);
            int rotateLeft16 = i20 ^ Integers.rotateLeft(rotateLeft15 + rotateLeft14, 18);
            i34 = rotateLeft7 ^ Integers.rotateLeft(rotateLeft4 + rotateLeft13, 7);
            i33 = rotateLeft10 ^ Integers.rotateLeft(i34 + rotateLeft4, 9);
            int rotateLeft17 = rotateLeft13 ^ Integers.rotateLeft(i33 + i34, 13);
            int rotateLeft18 = rotateLeft4 ^ Integers.rotateLeft(rotateLeft17 + i33, 18);
            i29 = rotateLeft11 ^ Integers.rotateLeft(rotateLeft8 + rotateLeft, 7);
            i28 = rotateLeft14 ^ Integers.rotateLeft(i29 + rotateLeft8, 9);
            int rotateLeft19 = Integers.rotateLeft(i28 + i29, 13) ^ rotateLeft;
            i30 = rotateLeft8 ^ Integers.rotateLeft(rotateLeft19 + i28, 18);
            i24 = rotateLeft15 ^ Integers.rotateLeft(rotateLeft12 + rotateLeft5, 7);
            int rotateLeft20 = Integers.rotateLeft(i24 + rotateLeft12, 9) ^ rotateLeft2;
            i26 = rotateLeft5 ^ Integers.rotateLeft(rotateLeft20 + i24, 13);
            i25 = rotateLeft12 ^ Integers.rotateLeft(i26 + rotateLeft20, 18);
            i23 = rotateLeft3 ^ Integers.rotateLeft(rotateLeft16 + rotateLeft9, 7);
            i22 = rotateLeft6 ^ Integers.rotateLeft(i23 + rotateLeft16, 9);
            i21 = rotateLeft9 ^ Integers.rotateLeft(i22 + i23, 13);
            i20 = rotateLeft16 ^ Integers.rotateLeft(i21 + i22, 18);
            i32 = rotateLeft17;
            i27 = rotateLeft20;
            i35 = rotateLeft18;
            i31 = rotateLeft19;
            c = 0;
            i17 = 13;
            i12 = 9;
            i9 = 7;
            i36 = i37 - 2;
        }
        char c2 = c;
        iArr2[c2] = i35 + iArr[c2];
        iArr2[1] = i34 + iArr[1];
        iArr2[2] = i33 + iArr[2];
        iArr2[3] = i32 + iArr[3];
        iArr2[4] = i31 + iArr[4];
        iArr2[5] = i30 + iArr[5];
        iArr2[6] = i29 + iArr[6];
        iArr2[7] = i28 + iArr[7];
        iArr2[8] = i27 + iArr[8];
        iArr2[9] = i26 + iArr[9];
        iArr2[10] = i25 + iArr[10];
        iArr2[11] = i24 + iArr[11];
        iArr2[12] = i23 + iArr[12];
        iArr2[13] = i22 + iArr[13];
        iArr2[14] = i21 + iArr[14];
        iArr2[15] = i20 + iArr[15];
    }

    protected void advanceCounter() {
        int[] iArr = this.engineState;
        int i = iArr[8] + 1;
        iArr[8] = i;
        if (i == 0) {
            iArr[9] = iArr[9] + 1;
        }
    }

    protected void advanceCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i > 0) {
            int[] iArr = this.engineState;
            iArr[9] = iArr[9] + i;
        }
        int[] iArr2 = this.engineState;
        int i3 = iArr2[8];
        int i4 = i2 + i3;
        iArr2[8] = i4;
        if (i3 == 0 || i4 >= i3) {
            return;
        }
        iArr2[9] = iArr2[9] + 1;
    }

    protected void generateKeyStream(byte[] bArr) {
        salsaCore(this.rounds, this.engineState, this.f687x);
        Pack.intToLittleEndian(this.f687x, bArr, 0);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return this.rounds != 20 ? "Salsa20/" + this.rounds : "Salsa20";
    }

    protected long getCounter() {
        int[] iArr = this.engineState;
        return (iArr[9] << 32) | (iArr[8] & BodyPartID.bodyIdMax);
    }

    protected int getNonceSize() {
        return 8;
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long getPosition() {
        return (getCounter() * 64) + this.index;
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
            byte[] key = ((KeyParameter) parameters).getKey();
            setKey(key, iv);
            CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties(getAlgorithmName(), key.length * 8, cipherParameters, Utils.getPurpose(z)));
        }
        reset();
        this.initialised = true;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void packTauOrSigma(int i, int[] iArr, int i2) {
        int i3 = (i - 16) / 4;
        int[] iArr2 = TAU_SIGMA;
        iArr[i2] = iArr2[i3];
        iArr[i2 + 1] = iArr2[i3 + 1];
        iArr[i2 + 2] = iArr2[i3 + 2];
        iArr[i2 + 3] = iArr2[i3 + 3];
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (this.initialised) {
            if (i + i2 <= bArr.length) {
                if (i3 + i2 <= bArr2.length) {
                    if (limitExceeded(i2)) {
                        throw new MaxBytesExceededException("2^70 byte limit per IV would be exceeded; Change IV");
                    }
                    for (int i4 = 0; i4 < i2; i4++) {
                        byte[] bArr3 = this.keyStream;
                        int i5 = this.index;
                        bArr2[i4 + i3] = (byte) (bArr3[i5] ^ bArr[i4 + i]);
                        int i6 = (i5 + 1) & 63;
                        this.index = i6;
                        if (i6 == 0) {
                            advanceCounter();
                            generateKeyStream(this.keyStream);
                        }
                    }
                    return i2;
                }
                throw new OutputLengthException("output buffer too short");
            }
            throw new DataLengthException("input buffer too short");
        }
        throw new IllegalStateException(getAlgorithmName() + " not initialised");
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        this.index = 0;
        resetLimitCounter();
        resetCounter();
        generateKeyStream(this.keyStream);
    }

    protected void resetCounter() {
        int[] iArr = this.engineState;
        iArr[9] = 0;
        iArr[8] = 0;
    }

    protected void retreatCounter() {
        int[] iArr = this.engineState;
        int i = iArr[8];
        if (i == 0 && iArr[9] == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        int i2 = i - 1;
        iArr[8] = i2;
        if (i2 == -1) {
            iArr[9] = iArr[9] - 1;
        }
    }

    protected void retreatCounter(long j) {
        int i = (int) (j >>> 32);
        int i2 = (int) j;
        if (i != 0) {
            int[] iArr = this.engineState;
            int i3 = iArr[9];
            if ((i3 & BodyPartID.bodyIdMax) < (i & BodyPartID.bodyIdMax)) {
                throw new IllegalStateException("attempt to reduce counter past zero.");
            }
            iArr[9] = i3 - i;
        }
        int[] iArr2 = this.engineState;
        int i4 = iArr2[8];
        if ((i4 & BodyPartID.bodyIdMax) >= (BodyPartID.bodyIdMax & i2)) {
            iArr2[8] = i4 - i2;
            return;
        }
        int i5 = iArr2[9];
        if (i5 == 0) {
            throw new IllegalStateException("attempt to reduce counter past zero.");
        }
        iArr2[9] = i5 - 1;
        iArr2[8] = i4 - i2;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        if (limitExceeded()) {
            throw new MaxBytesExceededException("2^70 byte limit per IV; Change IV");
        }
        byte[] bArr = this.keyStream;
        int i = this.index;
        byte b2 = (byte) (b ^ bArr[i]);
        int i2 = (i + 1) & 63;
        this.index = i2;
        if (i2 == 0) {
            advanceCounter();
            generateKeyStream(this.keyStream);
        }
        return b2;
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long seekTo(long j) {
        reset();
        return skip(j);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void setKey(byte[] bArr, byte[] bArr2) {
        if (bArr != null) {
            if (bArr.length != 16 && bArr.length != 32) {
                throw new IllegalArgumentException(getAlgorithmName() + " requires 128 bit or 256 bit key");
            }
            int length = (bArr.length - 16) / 4;
            int[] iArr = this.engineState;
            int[] iArr2 = TAU_SIGMA;
            iArr[0] = iArr2[length];
            iArr[5] = iArr2[length + 1];
            iArr[10] = iArr2[length + 2];
            iArr[15] = iArr2[length + 3];
            Pack.littleEndianToInt(bArr, 0, iArr, 1, 4);
            Pack.littleEndianToInt(bArr, bArr.length - 16, this.engineState, 11, 4);
        }
        Pack.littleEndianToInt(bArr2, 0, this.engineState, 6, 2);
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long skip(long j) {
        long j2;
        if (j >= 0) {
            if (j >= 64) {
                long j3 = j / 64;
                advanceCounter(j3);
                j2 = j - (j3 * 64);
            } else {
                j2 = j;
            }
            int i = this.index;
            int i2 = (((int) j2) + i) & 63;
            this.index = i2;
            if (i2 < i) {
                advanceCounter();
            }
        } else {
            long j4 = -j;
            if (j4 >= 64) {
                long j5 = j4 / 64;
                retreatCounter(j5);
                j4 -= j5 * 64;
            }
            for (long j6 = 0; j6 < j4; j6++) {
                if (this.index == 0) {
                    retreatCounter();
                }
                this.index = (this.index - 1) & 63;
            }
        }
        generateKeyStream(this.keyStream);
        return j;
    }
}