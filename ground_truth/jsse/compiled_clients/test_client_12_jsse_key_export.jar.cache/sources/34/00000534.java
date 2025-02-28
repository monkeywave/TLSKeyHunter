package org.bouncycastle.crypto.paddings;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/paddings/PaddedBufferedBlockCipher.class */
public class PaddedBufferedBlockCipher extends BufferedBlockCipher {
    BlockCipherPadding padding;

    public PaddedBufferedBlockCipher(BlockCipher blockCipher, BlockCipherPadding blockCipherPadding) {
        this.cipher = blockCipher;
        this.padding = blockCipherPadding;
        this.buf = new byte[blockCipher.getBlockSize()];
        this.bufOff = 0;
    }

    public PaddedBufferedBlockCipher(BlockCipher blockCipher) {
        this(blockCipher, new PKCS7Padding());
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        reset();
        if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.padding.init(null);
            this.cipher.init(z, cipherParameters);
            return;
        }
        ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
        this.padding.init(parametersWithRandom.getRandom());
        this.cipher.init(z, parametersWithRandom.getParameters());
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public int getOutputSize(int i) {
        int i2 = i + this.bufOff;
        int length = i2 % this.buf.length;
        return length == 0 ? this.forEncryption ? i2 + this.buf.length : i2 : (i2 - length) + this.buf.length;
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public int getUpdateOutputSize(int i) {
        int i2 = i + this.bufOff;
        int length = i2 % this.buf.length;
        return length == 0 ? Math.max(0, i2 - this.buf.length) : i2 - length;
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        int i2 = 0;
        if (this.bufOff == this.buf.length) {
            i2 = this.cipher.processBlock(this.buf, 0, bArr, i);
            this.bufOff = 0;
        }
        byte[] bArr2 = this.buf;
        int i3 = this.bufOff;
        this.bufOff = i3 + 1;
        bArr2[i3] = b;
        return i2;
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException, IllegalStateException {
        if (i2 < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int blockSize = getBlockSize();
        int updateOutputSize = getUpdateOutputSize(i2);
        if (updateOutputSize <= 0 || i3 + updateOutputSize <= bArr2.length) {
            int i4 = 0;
            int length = this.buf.length - this.bufOff;
            if (i2 > length) {
                System.arraycopy(bArr, i, this.buf, this.bufOff, length);
                i4 = 0 + this.cipher.processBlock(this.buf, 0, bArr2, i3);
                this.bufOff = 0;
                i2 -= length;
                int i5 = i;
                int i6 = length;
                while (true) {
                    i = i5 + i6;
                    if (i2 <= this.buf.length) {
                        break;
                    }
                    i4 += this.cipher.processBlock(bArr, i, bArr2, i3 + i4);
                    i2 -= blockSize;
                    i5 = i;
                    i6 = blockSize;
                }
            }
            System.arraycopy(bArr, i, this.buf, this.bufOff, i2);
            this.bufOff += i2;
            return i4;
        }
        throw new OutputLengthException("output buffer too short");
    }

    @Override // org.bouncycastle.crypto.BufferedBlockCipher
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        int padCount;
        int blockSize = this.cipher.getBlockSize();
        int i2 = 0;
        if (this.forEncryption) {
            if (this.bufOff == blockSize) {
                if (i + (2 * blockSize) > bArr.length) {
                    reset();
                    throw new OutputLengthException("output buffer too short");
                }
                i2 = this.cipher.processBlock(this.buf, 0, bArr, i);
                this.bufOff = 0;
            }
            this.padding.addPadding(this.buf, this.bufOff);
            padCount = i2 + this.cipher.processBlock(this.buf, 0, bArr, i + i2);
            reset();
        } else if (this.bufOff != blockSize) {
            reset();
            throw new DataLengthException("last block incomplete in decryption");
        } else {
            int processBlock = this.cipher.processBlock(this.buf, 0, this.buf, 0);
            this.bufOff = 0;
            try {
                padCount = processBlock - this.padding.padCount(this.buf);
                System.arraycopy(this.buf, 0, bArr, i, padCount);
                reset();
            } catch (Throwable th) {
                reset();
                throw th;
            }
        }
        return padCount;
    }
}