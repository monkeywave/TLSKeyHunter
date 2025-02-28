package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/G3413OFBBlockCipher.class */
public class G3413OFBBlockCipher extends StreamBlockCipher {

    /* renamed from: m */
    private int f462m;
    private int blockSize;

    /* renamed from: R */
    private byte[] f463R;
    private byte[] R_init;

    /* renamed from: Y */
    private byte[] f464Y;
    private BlockCipher cipher;
    private int byteCount;
    private boolean initialized;

    public G3413OFBBlockCipher(BlockCipher blockCipher) {
        super(blockCipher);
        this.initialized = false;
        this.blockSize = blockCipher.getBlockSize();
        this.cipher = blockCipher;
        this.f464Y = new byte[this.blockSize];
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            if (iv.length < this.blockSize) {
                throw new IllegalArgumentException("Parameter m must blockSize <= m");
            }
            this.f462m = iv.length;
            initArrays();
            this.R_init = Arrays.clone(iv);
            System.arraycopy(this.R_init, 0, this.f463R, 0, this.R_init.length);
            if (parametersWithIV.getParameters() != null) {
                this.cipher.init(true, parametersWithIV.getParameters());
            }
        } else {
            setupDefaultParams();
            initArrays();
            System.arraycopy(this.R_init, 0, this.f463R, 0, this.R_init.length);
            if (cipherParameters != null) {
                this.cipher.init(true, cipherParameters);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.f463R = new byte[this.f462m];
        this.R_init = new byte[this.f462m];
    }

    private void setupDefaultParams() {
        this.f462m = 2 * this.blockSize;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/OFB";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.blockSize;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        processBytes(bArr, i, this.blockSize, bArr2, i2);
        return this.blockSize;
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher
    protected byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            generateY();
        }
        byte b2 = (byte) (this.f464Y[this.byteCount] ^ b);
        this.byteCount++;
        if (this.byteCount == getBlockSize()) {
            this.byteCount = 0;
            generateR();
        }
        return b2;
    }

    private void generateY() {
        this.cipher.processBlock(GOST3413CipherUtil.MSB(this.f463R, this.blockSize), 0, this.f464Y, 0);
    }

    private void generateR() {
        byte[] LSB = GOST3413CipherUtil.LSB(this.f463R, this.f462m - this.blockSize);
        System.arraycopy(LSB, 0, this.f463R, 0, LSB.length);
        System.arraycopy(this.f464Y, 0, this.f463R, LSB.length, this.f462m - LSB.length);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.R_init, 0, this.f463R, 0, this.R_init.length);
            Arrays.clear(this.f464Y);
            this.byteCount = 0;
            this.cipher.reset();
        }
    }
}