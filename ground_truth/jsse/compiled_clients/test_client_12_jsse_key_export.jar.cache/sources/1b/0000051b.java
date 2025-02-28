package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/PaddedBlockCipher.class */
public class PaddedBlockCipher extends BufferedBlockCipher {
    public PaddedBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
        this.buf = new byte[blockCipher.getBlockSize()];
        this.bufOff = 0;
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
        return length == 0 ? i2 - this.buf.length : i2 - length;
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
        int i2;
        int blockSize = this.cipher.getBlockSize();
        int i3 = 0;
        if (this.forEncryption) {
            if (this.bufOff == blockSize) {
                if (i + (2 * blockSize) > bArr.length) {
                    throw new OutputLengthException("output buffer too short");
                }
                i3 = this.cipher.processBlock(this.buf, 0, bArr, i);
                this.bufOff = 0;
            }
            byte b = (byte) (blockSize - this.bufOff);
            while (this.bufOff < blockSize) {
                this.buf[this.bufOff] = b;
                this.bufOff++;
            }
            i2 = i3 + this.cipher.processBlock(this.buf, 0, bArr, i + i3);
        } else if (this.bufOff != blockSize) {
            throw new DataLengthException("last block incomplete in decryption");
        } else {
            int processBlock = this.cipher.processBlock(this.buf, 0, this.buf, 0);
            this.bufOff = 0;
            int i4 = this.buf[blockSize - 1] & 255;
            if (i4 > blockSize) {
                throw new InvalidCipherTextException("pad block corrupted");
            }
            i2 = processBlock - i4;
            System.arraycopy(this.buf, 0, bArr, i, i2);
        }
        reset();
        return i2;
    }
}