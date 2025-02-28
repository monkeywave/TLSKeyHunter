package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/CBCBlockCipher.class */
public class CBCBlockCipher implements BlockCipher {

    /* renamed from: IV */
    private byte[] f453IV;
    private byte[] cbcV;
    private byte[] cbcNextV;
    private int blockSize;
    private BlockCipher cipher;
    private boolean encrypting;

    public CBCBlockCipher(BlockCipher blockCipher) {
        this.cipher = null;
        this.cipher = blockCipher;
        this.blockSize = blockCipher.getBlockSize();
        this.f453IV = new byte[this.blockSize];
        this.cbcV = new byte[this.blockSize];
        this.cbcNextV = new byte[this.blockSize];
    }

    public BlockCipher getUnderlyingCipher() {
        return this.cipher;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        boolean z2 = this.encrypting;
        this.encrypting = z;
        if (!(cipherParameters instanceof ParametersWithIV)) {
            reset();
            if (cipherParameters != null) {
                this.cipher.init(z, cipherParameters);
                return;
            } else if (z2 != z) {
                throw new IllegalArgumentException("cannot change encrypting state without providing key.");
            } else {
                return;
            }
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        if (iv.length != this.blockSize) {
            throw new IllegalArgumentException("initialisation vector must be the same length as block size");
        }
        System.arraycopy(iv, 0, this.f453IV, 0, iv.length);
        reset();
        if (parametersWithIV.getParameters() != null) {
            this.cipher.init(z, parametersWithIV.getParameters());
        } else if (z2 != z) {
            throw new IllegalArgumentException("cannot change encrypting state without providing key.");
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CBC";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        return this.encrypting ? encryptBlock(bArr, i, bArr2, i2) : decryptBlock(bArr, i, bArr2, i2);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        System.arraycopy(this.f453IV, 0, this.cbcV, 0, this.f453IV.length);
        Arrays.fill(this.cbcNextV, (byte) 0);
        this.cipher.reset();
    }

    private int encryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        for (int i3 = 0; i3 < this.blockSize; i3++) {
            byte[] bArr3 = this.cbcV;
            int i4 = i3;
            bArr3[i4] = (byte) (bArr3[i4] ^ bArr[i + i3]);
        }
        int processBlock = this.cipher.processBlock(this.cbcV, 0, bArr2, i2);
        System.arraycopy(bArr2, i2, this.cbcV, 0, this.cbcV.length);
        return processBlock;
    }

    private int decryptBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        if (i + this.blockSize > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        System.arraycopy(bArr, i, this.cbcNextV, 0, this.blockSize);
        int processBlock = this.cipher.processBlock(bArr, i, bArr2, i2);
        for (int i3 = 0; i3 < this.blockSize; i3++) {
            int i4 = i2 + i3;
            bArr2[i4] = (byte) (bArr2[i4] ^ this.cbcV[i3]);
        }
        byte[] bArr3 = this.cbcV;
        this.cbcV = this.cbcNextV;
        this.cbcNextV = bArr3;
        return processBlock;
    }
}