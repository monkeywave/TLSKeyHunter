package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/OpenPGPCFBBlockCipher.class */
public class OpenPGPCFBBlockCipher implements BlockCipher {

    /* renamed from: IV */
    private byte[] f481IV;

    /* renamed from: FR */
    private byte[] f482FR;
    private byte[] FRE;
    private BlockCipher cipher;
    private int count;
    private int blockSize;
    private boolean forEncryption;

    public OpenPGPCFBBlockCipher(BlockCipher blockCipher) {
        this.cipher = blockCipher;
        this.blockSize = blockCipher.getBlockSize();
        this.f481IV = new byte[this.blockSize];
        this.f482FR = new byte[this.blockSize];
        this.FRE = new byte[this.blockSize];
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/OpenPGPCFB";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        return this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        this.count = 0;
        System.arraycopy(this.f481IV, 0, this.f482FR, 0, this.f482FR.length);
        this.cipher.reset();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        reset();
        this.cipher.init(true, cipherParameters);
    }

    private byte encryptByte(byte b, int i) {
        return (byte) (this.FRE[i] ^ b);
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + this.blockSize > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.count > this.blockSize) {
            byte encryptByte = encryptByte(bArr[i], this.blockSize - 2);
            bArr2[i2] = encryptByte;
            this.f482FR[this.blockSize - 2] = encryptByte;
            byte encryptByte2 = encryptByte(bArr[i + 1], this.blockSize - 1);
            bArr2[i2 + 1] = encryptByte2;
            this.f482FR[this.blockSize - 1] = encryptByte2;
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i3 = 2; i3 < this.blockSize; i3++) {
                byte encryptByte3 = encryptByte(bArr[i + i3], i3 - 2);
                bArr2[i2 + i3] = encryptByte3;
                this.f482FR[i3 - 2] = encryptByte3;
            }
        } else if (this.count == 0) {
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i4 = 0; i4 < this.blockSize; i4++) {
                byte encryptByte4 = encryptByte(bArr[i + i4], i4);
                bArr2[i2 + i4] = encryptByte4;
                this.f482FR[i4] = encryptByte4;
            }
            this.count += this.blockSize;
        } else if (this.count == this.blockSize) {
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            bArr2[i2] = encryptByte(bArr[i], 0);
            bArr2[i2 + 1] = encryptByte(bArr[i + 1], 1);
            System.arraycopy(this.f482FR, 2, this.f482FR, 0, this.blockSize - 2);
            System.arraycopy(bArr2, i2, this.f482FR, this.blockSize - 2, 2);
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i5 = 2; i5 < this.blockSize; i5++) {
                byte encryptByte5 = encryptByte(bArr[i + i5], i5 - 2);
                bArr2[i2 + i5] = encryptByte5;
                this.f482FR[i5 - 2] = encryptByte5;
            }
            this.count += this.blockSize;
        }
        return this.blockSize;
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + this.blockSize > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.count > this.blockSize) {
            byte b = bArr[i];
            this.f482FR[this.blockSize - 2] = b;
            bArr2[i2] = encryptByte(b, this.blockSize - 2);
            byte b2 = bArr[i + 1];
            this.f482FR[this.blockSize - 1] = b2;
            bArr2[i2 + 1] = encryptByte(b2, this.blockSize - 1);
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i3 = 2; i3 < this.blockSize; i3++) {
                byte b3 = bArr[i + i3];
                this.f482FR[i3 - 2] = b3;
                bArr2[i2 + i3] = encryptByte(b3, i3 - 2);
            }
        } else if (this.count == 0) {
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i4 = 0; i4 < this.blockSize; i4++) {
                this.f482FR[i4] = bArr[i + i4];
                bArr2[i4] = encryptByte(bArr[i + i4], i4);
            }
            this.count += this.blockSize;
        } else if (this.count == this.blockSize) {
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            byte b4 = bArr[i];
            byte b5 = bArr[i + 1];
            bArr2[i2] = encryptByte(b4, 0);
            bArr2[i2 + 1] = encryptByte(b5, 1);
            System.arraycopy(this.f482FR, 2, this.f482FR, 0, this.blockSize - 2);
            this.f482FR[this.blockSize - 2] = b4;
            this.f482FR[this.blockSize - 1] = b5;
            this.cipher.processBlock(this.f482FR, 0, this.FRE, 0);
            for (int i5 = 2; i5 < this.blockSize; i5++) {
                byte b6 = bArr[i + i5];
                this.f482FR[i5 - 2] = b6;
                bArr2[i2 + i5] = encryptByte(b6, i5 - 2);
            }
            this.count += this.blockSize;
        }
        return this.blockSize;
    }
}