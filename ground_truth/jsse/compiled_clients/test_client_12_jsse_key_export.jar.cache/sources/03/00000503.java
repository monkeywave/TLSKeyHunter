package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/G3413CBCBlockCipher.class */
public class G3413CBCBlockCipher implements BlockCipher {

    /* renamed from: m */
    private int f455m;
    private int blockSize;

    /* renamed from: R */
    private byte[] f456R;
    private byte[] R_init;
    private BlockCipher cipher;
    private boolean initialized = false;
    private boolean forEncryption;

    public G3413CBCBlockCipher(BlockCipher blockCipher) {
        this.blockSize = blockCipher.getBlockSize();
        this.cipher = blockCipher;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.forEncryption = z;
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            if (iv.length < this.blockSize) {
                throw new IllegalArgumentException("Parameter m must blockSize <= m");
            }
            this.f455m = iv.length;
            initArrays();
            this.R_init = Arrays.clone(iv);
            System.arraycopy(this.R_init, 0, this.f456R, 0, this.R_init.length);
            if (parametersWithIV.getParameters() != null) {
                this.cipher.init(z, parametersWithIV.getParameters());
            }
        } else {
            setupDefaultParams();
            initArrays();
            System.arraycopy(this.R_init, 0, this.f456R, 0, this.R_init.length);
            if (cipherParameters != null) {
                this.cipher.init(z, cipherParameters);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.f456R = new byte[this.f455m];
        this.R_init = new byte[this.f455m];
    }

    private void setupDefaultParams() {
        this.f455m = this.blockSize;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/CBC";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.blockSize;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        return this.forEncryption ? encrypt(bArr, i, bArr2, i2) : decrypt(bArr, i, bArr2, i2);
    }

    private int encrypt(byte[] bArr, int i, byte[] bArr2, int i2) {
        byte[] sum = GOST3413CipherUtil.sum(GOST3413CipherUtil.copyFromInput(bArr, this.blockSize, i), GOST3413CipherUtil.MSB(this.f456R, this.blockSize));
        byte[] bArr3 = new byte[sum.length];
        this.cipher.processBlock(sum, 0, bArr3, 0);
        System.arraycopy(bArr3, 0, bArr2, i2, bArr3.length);
        if (bArr2.length > i2 + sum.length) {
            generateR(bArr3);
        }
        return bArr3.length;
    }

    private int decrypt(byte[] bArr, int i, byte[] bArr2, int i2) {
        byte[] MSB = GOST3413CipherUtil.MSB(this.f456R, this.blockSize);
        byte[] copyFromInput = GOST3413CipherUtil.copyFromInput(bArr, this.blockSize, i);
        byte[] bArr3 = new byte[copyFromInput.length];
        this.cipher.processBlock(copyFromInput, 0, bArr3, 0);
        byte[] sum = GOST3413CipherUtil.sum(bArr3, MSB);
        System.arraycopy(sum, 0, bArr2, i2, sum.length);
        if (bArr2.length > i2 + sum.length) {
            generateR(copyFromInput);
        }
        return sum.length;
    }

    private void generateR(byte[] bArr) {
        byte[] LSB = GOST3413CipherUtil.LSB(this.f456R, this.f455m - this.blockSize);
        System.arraycopy(LSB, 0, this.f456R, 0, LSB.length);
        System.arraycopy(bArr, 0, this.f456R, LSB.length, this.f455m - LSB.length);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.R_init, 0, this.f456R, 0, this.R_init.length);
            this.cipher.reset();
        }
    }
}