package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.SkippingStreamCipher;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/SICBlockCipher.class */
public class SICBlockCipher extends StreamBlockCipher implements SkippingStreamCipher {
    private final BlockCipher cipher;
    private final int blockSize;

    /* renamed from: IV */
    private byte[] f485IV;
    private byte[] counter;
    private byte[] counterOut;
    private int byteCount;

    public SICBlockCipher(BlockCipher blockCipher) {
        super(blockCipher);
        this.cipher = blockCipher;
        this.blockSize = this.cipher.getBlockSize();
        this.f485IV = new byte[this.blockSize];
        this.counter = new byte[this.blockSize];
        this.counterOut = new byte[this.blockSize];
        this.byteCount = 0;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("CTR/SIC mode requires ParametersWithIV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        this.f485IV = Arrays.clone(parametersWithIV.getIV());
        if (this.blockSize < this.f485IV.length) {
            throw new IllegalArgumentException("CTR/SIC mode requires IV no greater than: " + this.blockSize + " bytes.");
        }
        int i = 8 > this.blockSize / 2 ? this.blockSize / 2 : 8;
        if (this.blockSize - this.f485IV.length > i) {
            throw new IllegalArgumentException("CTR/SIC mode requires IV of at least: " + (this.blockSize - i) + " bytes.");
        }
        if (parametersWithIV.getParameters() != null) {
            this.cipher.init(true, parametersWithIV.getParameters());
        }
        reset();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/SIC";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (this.byteCount != 0) {
            processBytes(bArr, i, this.blockSize, bArr2, i2);
            return this.blockSize;
        } else if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too small");
        } else {
            if (i2 + this.blockSize > bArr2.length) {
                throw new OutputLengthException("output buffer too short");
            }
            this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
            for (int i3 = 0; i3 < this.blockSize; i3++) {
                bArr2[i2 + i3] = (byte) (bArr[i + i3] ^ this.counterOut[i3]);
            }
            incrementCounterChecked();
            return this.blockSize;
        }
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher, org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        byte b;
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too small");
        }
        if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        for (int i4 = 0; i4 < i2; i4++) {
            if (this.byteCount == 0) {
                this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
                byte b2 = bArr[i + i4];
                byte[] bArr3 = this.counterOut;
                int i5 = this.byteCount;
                this.byteCount = i5 + 1;
                b = (byte) (b2 ^ bArr3[i5]);
            } else {
                byte b3 = bArr[i + i4];
                byte[] bArr4 = this.counterOut;
                int i6 = this.byteCount;
                this.byteCount = i6 + 1;
                b = (byte) (b3 ^ bArr4[i6]);
                if (this.byteCount == this.counter.length) {
                    this.byteCount = 0;
                    incrementCounterChecked();
                }
            }
            bArr2[i3 + i4] = b;
        }
        return i2;
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher
    protected byte calculateByte(byte b) throws DataLengthException, IllegalStateException {
        if (this.byteCount == 0) {
            this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
            byte[] bArr = this.counterOut;
            int i = this.byteCount;
            this.byteCount = i + 1;
            return (byte) (bArr[i] ^ b);
        }
        byte[] bArr2 = this.counterOut;
        int i2 = this.byteCount;
        this.byteCount = i2 + 1;
        byte b2 = (byte) (bArr2[i2] ^ b);
        if (this.byteCount == this.counter.length) {
            this.byteCount = 0;
            incrementCounterChecked();
        }
        return b2;
    }

    private void checkCounter() {
        if (this.f485IV.length < this.blockSize) {
            for (int i = 0; i != this.f485IV.length; i++) {
                if (this.counter[i] != this.f485IV[i]) {
                    throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
                }
            }
        }
    }

    private void incrementCounterChecked() {
        byte b;
        int length = this.counter.length;
        do {
            length--;
            if (length < 0) {
                break;
            }
            byte[] bArr = this.counter;
            b = (byte) (bArr[length] + 1);
            bArr[length] = b;
        } while (b == 0);
        if (length < this.f485IV.length && this.f485IV.length < this.blockSize) {
            throw new IllegalStateException("Counter in CTR/SIC mode out of range.");
        }
    }

    private void incrementCounterAt(int i) {
        byte b;
        int length = this.counter.length - i;
        do {
            length--;
            if (length < 0) {
                return;
            }
            byte[] bArr = this.counter;
            b = (byte) (bArr[length] + 1);
            bArr[length] = b;
        } while (b == 0);
    }

    private void incrementCounter(int i) {
        byte b = this.counter[this.counter.length - 1];
        byte[] bArr = this.counter;
        int length = this.counter.length - 1;
        bArr[length] = (byte) (bArr[length] + i);
        if (b == 0 || this.counter[this.counter.length - 1] >= b) {
            return;
        }
        incrementCounterAt(1);
    }

    private void decrementCounterAt(int i) {
        byte b;
        int length = this.counter.length - i;
        do {
            length--;
            if (length < 0) {
                return;
            }
            byte[] bArr = this.counter;
            b = (byte) (bArr[length] - 1);
            bArr[length] = b;
        } while (b == -1);
    }

    private void adjustCounter(long j) {
        if (j >= 0) {
            long j2 = (j + this.byteCount) / this.blockSize;
            long j3 = j2;
            if (j3 > 255) {
                for (int i = 5; i >= 1; i--) {
                    long j4 = 1 << (8 * i);
                    while (j3 >= j4) {
                        incrementCounterAt(i);
                        j3 -= j4;
                    }
                }
            }
            incrementCounter((int) j3);
            this.byteCount = (int) ((j + this.byteCount) - (this.blockSize * j2));
            return;
        }
        long j5 = ((-j) - this.byteCount) / this.blockSize;
        long j6 = j5;
        if (j6 > 255) {
            for (int i2 = 5; i2 >= 1; i2--) {
                long j7 = 1 << (8 * i2);
                while (j6 > j7) {
                    decrementCounterAt(i2);
                    j6 -= j7;
                }
            }
        }
        long j8 = 0;
        while (true) {
            long j9 = j8;
            if (j9 == j6) {
                break;
            }
            decrementCounterAt(0);
            j8 = j9 + 1;
        }
        int i3 = (int) (this.byteCount + j + (this.blockSize * j5));
        if (i3 >= 0) {
            this.byteCount = 0;
            return;
        }
        decrementCounterAt(0);
        this.byteCount = this.blockSize + i3;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        Arrays.fill(this.counter, (byte) 0);
        System.arraycopy(this.f485IV, 0, this.counter, 0, this.f485IV.length);
        this.cipher.reset();
        this.byteCount = 0;
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long skip(long j) {
        adjustCounter(j);
        checkCounter();
        this.cipher.processBlock(this.counter, 0, this.counterOut, 0);
        return j;
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long seekTo(long j) {
        reset();
        return skip(j);
    }

    @Override // org.bouncycastle.crypto.SkippingCipher
    public long getPosition() {
        byte[] bArr = new byte[this.counter.length];
        System.arraycopy(this.counter, 0, bArr, 0, bArr.length);
        int length = bArr.length - 1;
        while (length >= 1) {
            int i = length < this.f485IV.length ? (bArr[length] & 255) - (this.f485IV[length] & 255) : bArr[length] & 255;
            if (i < 0) {
                int i2 = length - 1;
                bArr[i2] = (byte) (bArr[i2] - 1);
                i += 256;
            }
            bArr[length] = (byte) i;
            length--;
        }
        return (Pack.bigEndianToLong(bArr, bArr.length - 8) * this.blockSize) + this.byteCount;
    }
}