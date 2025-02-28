package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/PGPCFBBlockCipher.class */
public class PGPCFBBlockCipher implements BlockCipher {

    /* renamed from: IV */
    private byte[] f483IV;

    /* renamed from: FR */
    private byte[] f484FR;
    private byte[] FRE;
    private byte[] tmp;
    private BlockCipher cipher;
    private int count;
    private int blockSize;
    private boolean forEncryption;
    private boolean inlineIv;

    public PGPCFBBlockCipher(BlockCipher blockCipher, boolean z) {
        this.cipher = blockCipher;
        this.inlineIv = z;
        this.blockSize = blockCipher.getBlockSize();
        this.f483IV = new byte[this.blockSize];
        this.f484FR = new byte[this.blockSize];
        this.FRE = new byte[this.blockSize];
        this.tmp = new byte[this.blockSize];
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.inlineIv ? this.cipher.getAlgorithmName() + "/PGPCFBwithIV" : this.cipher.getAlgorithmName() + "/PGPCFB";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        return this.inlineIv ? this.forEncryption ? encryptBlockWithIV(bArr, i, bArr2, i2) : decryptBlockWithIV(bArr, i, bArr2, i2) : this.forEncryption ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        this.count = 0;
        for (int i = 0; i != this.f484FR.length; i++) {
            if (this.inlineIv) {
                this.f484FR[i] = 0;
            } else {
                this.f484FR[i] = this.f483IV[i];
            }
        }
        this.cipher.reset();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        if (!(cipherParameters instanceof ParametersWithIV)) {
            reset();
            this.cipher.init(true, cipherParameters);
            return;
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        if (iv.length < this.f483IV.length) {
            System.arraycopy(iv, 0, this.f483IV, this.f483IV.length - iv.length, iv.length);
            for (int i = 0; i < this.f483IV.length - iv.length; i++) {
                this.f483IV[i] = 0;
            }
        } else {
            System.arraycopy(iv, 0, this.f483IV, 0, this.f483IV.length);
        }
        reset();
        this.cipher.init(true, parametersWithIV.getParameters());
    }

    private byte encryptByte(byte b, int i) {
        return (byte) (this.FRE[i] ^ b);
    }

    private int encryptBlockWithIV(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (this.count != 0) {
            if (this.count >= this.blockSize + 2) {
                if (i2 + this.blockSize > bArr2.length) {
                    throw new OutputLengthException("output buffer too short");
                }
                this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
                for (int i3 = 0; i3 < this.blockSize; i3++) {
                    bArr2[i2 + i3] = encryptByte(bArr[i + i3], i3);
                }
                System.arraycopy(bArr2, i2, this.f484FR, 0, this.blockSize);
            }
            return this.blockSize;
        } else if (i2 + (2 * this.blockSize) + 2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        } else {
            this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
            for (int i4 = 0; i4 < this.blockSize; i4++) {
                bArr2[i2 + i4] = encryptByte(this.f483IV[i4], i4);
            }
            System.arraycopy(bArr2, i2, this.f484FR, 0, this.blockSize);
            this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
            bArr2[i2 + this.blockSize] = encryptByte(this.f483IV[this.blockSize - 2], 0);
            bArr2[i2 + this.blockSize + 1] = encryptByte(this.f483IV[this.blockSize - 1], 1);
            System.arraycopy(bArr2, i2 + 2, this.f484FR, 0, this.blockSize);
            this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
            for (int i5 = 0; i5 < this.blockSize; i5++) {
                bArr2[i2 + this.blockSize + 2 + i5] = encryptByte(bArr[i + i5], i5);
            }
            System.arraycopy(bArr2, i2 + this.blockSize + 2, this.f484FR, 0, this.blockSize);
            this.count += (2 * this.blockSize) + 2;
            return (2 * this.blockSize) + 2;
        }
    }

    private int decryptBlockWithIV(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + this.blockSize > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        if (this.count == 0) {
            for (int i3 = 0; i3 < this.blockSize; i3++) {
                this.f484FR[i3] = bArr[i + i3];
            }
            this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
            this.count += this.blockSize;
            return 0;
        } else if (this.count == this.blockSize) {
            System.arraycopy(bArr, i, this.tmp, 0, this.blockSize);
            System.arraycopy(this.f484FR, 2, this.f484FR, 0, this.blockSize - 2);
            this.f484FR[this.blockSize - 2] = this.tmp[0];
            this.f484FR[this.blockSize - 1] = this.tmp[1];
            this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
            for (int i4 = 0; i4 < this.blockSize - 2; i4++) {
                bArr2[i2 + i4] = encryptByte(this.tmp[i4 + 2], i4);
            }
            System.arraycopy(this.tmp, 2, this.f484FR, 0, this.blockSize - 2);
            this.count += 2;
            return this.blockSize - 2;
        } else {
            if (this.count >= this.blockSize + 2) {
                System.arraycopy(bArr, i, this.tmp, 0, this.blockSize);
                bArr2[i2 + 0] = encryptByte(this.tmp[0], this.blockSize - 2);
                bArr2[i2 + 1] = encryptByte(this.tmp[1], this.blockSize - 1);
                System.arraycopy(this.tmp, 0, this.f484FR, this.blockSize - 2, 2);
                this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
                for (int i5 = 0; i5 < this.blockSize - 2; i5++) {
                    bArr2[i2 + i5 + 2] = encryptByte(this.tmp[i5 + 2], i5);
                }
                System.arraycopy(this.tmp, 2, this.f484FR, 0, this.blockSize - 2);
            }
            return this.blockSize;
        }
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i2 + this.blockSize > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
        for (int i3 = 0; i3 < this.blockSize; i3++) {
            bArr2[i2 + i3] = encryptByte(bArr[i + i3], i3);
        }
        for (int i4 = 0; i4 < this.blockSize; i4++) {
            this.f484FR[i4] = bArr2[i2 + i4];
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
        this.cipher.processBlock(this.f484FR, 0, this.FRE, 0);
        for (int i3 = 0; i3 < this.blockSize; i3++) {
            bArr2[i2 + i3] = encryptByte(bArr[i + i3], i3);
        }
        for (int i4 = 0; i4 < this.blockSize; i4++) {
            this.f484FR[i4] = bArr[i + i4];
        }
        return this.blockSize;
    }
}