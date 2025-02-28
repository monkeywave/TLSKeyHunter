package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/G3413CTRBlockCipher.class */
public class G3413CTRBlockCipher extends StreamBlockCipher {

    /* renamed from: s */
    private final int f460s;
    private byte[] CTR;

    /* renamed from: IV */
    private byte[] f461IV;
    private byte[] buf;
    private final int blockSize;
    private final BlockCipher cipher;
    private int byteCount;
    private boolean initialized;

    public G3413CTRBlockCipher(BlockCipher blockCipher) {
        this(blockCipher, blockCipher.getBlockSize() * 8);
    }

    public G3413CTRBlockCipher(BlockCipher blockCipher, int i) {
        super(blockCipher);
        this.byteCount = 0;
        if (i < 0 || i > blockCipher.getBlockSize() * 8) {
            throw new IllegalArgumentException("Parameter bitBlockSize must be in range 0 < bitBlockSize <= " + (blockCipher.getBlockSize() * 8));
        }
        this.cipher = blockCipher;
        this.blockSize = blockCipher.getBlockSize();
        this.f460s = i / 8;
        this.CTR = new byte[this.blockSize];
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters instanceof ParametersWithIV) {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            initArrays();
            this.f461IV = Arrays.clone(parametersWithIV.getIV());
            if (this.f461IV.length != this.blockSize / 2) {
                throw new IllegalArgumentException("Parameter IV length must be == blockSize/2");
            }
            System.arraycopy(this.f461IV, 0, this.CTR, 0, this.f461IV.length);
            for (int length = this.f461IV.length; length < this.blockSize; length++) {
                this.CTR[length] = 0;
            }
            if (parametersWithIV.getParameters() != null) {
                this.cipher.init(true, parametersWithIV.getParameters());
            }
        } else {
            initArrays();
            if (cipherParameters != null) {
                this.cipher.init(true, cipherParameters);
            }
        }
        this.initialized = true;
    }

    private void initArrays() {
        this.f461IV = new byte[this.blockSize / 2];
        this.CTR = new byte[this.blockSize];
        this.buf = new byte[this.f460s];
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/GCTR";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.f460s;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        processBytes(bArr, i, this.f460s, bArr2, i2);
        return this.f460s;
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher
    protected byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            this.buf = generateBuf();
        }
        byte b2 = (byte) (this.buf[this.byteCount] ^ b);
        this.byteCount++;
        if (this.byteCount == this.f460s) {
            this.byteCount = 0;
            generateCRT();
        }
        return b2;
    }

    private void generateCRT() {
        byte[] bArr = this.CTR;
        int length = this.CTR.length - 1;
        bArr[length] = (byte) (bArr[length] + 1);
    }

    private byte[] generateBuf() {
        byte[] bArr = new byte[this.CTR.length];
        this.cipher.processBlock(this.CTR, 0, bArr, 0);
        return GOST3413CipherUtil.MSB(bArr, this.f460s);
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        if (this.initialized) {
            System.arraycopy(this.f461IV, 0, this.CTR, 0, this.f461IV.length);
            for (int length = this.f461IV.length; length < this.blockSize; length++) {
                this.CTR[length] = 0;
            }
            this.byteCount = 0;
            this.cipher.reset();
        }
    }
}