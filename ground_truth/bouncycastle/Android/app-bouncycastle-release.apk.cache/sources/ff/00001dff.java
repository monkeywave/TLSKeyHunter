package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class G3413CTRBlockCipher extends StreamBlockCipher {
    private byte[] CTR;

    /* renamed from: IV */
    private byte[] f778IV;
    private final int blockSize;
    private byte[] buf;
    private int byteCount;
    private final BlockCipher cipher;
    private boolean initialized;

    /* renamed from: s */
    private final int f779s;

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
        int blockSize = blockCipher.getBlockSize();
        this.blockSize = blockSize;
        this.f779s = i / 8;
        this.CTR = new byte[blockSize];
    }

    private byte[] generateBuf() {
        byte[] bArr = this.CTR;
        byte[] bArr2 = new byte[bArr.length];
        this.cipher.processBlock(bArr, 0, bArr2, 0);
        return GOST3413CipherUtil.MSB(bArr2, this.f779s);
    }

    private void generateCRT() {
        byte[] bArr = this.CTR;
        int length = bArr.length - 1;
        bArr[length] = (byte) (bArr[length] + 1);
    }

    private void initArrays() {
        int i = this.blockSize;
        this.f778IV = new byte[i / 2];
        this.CTR = new byte[i];
        this.buf = new byte[this.f779s];
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher
    protected byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            this.buf = generateBuf();
        }
        byte[] bArr = this.buf;
        int i = this.byteCount;
        byte b2 = (byte) (b ^ bArr[i]);
        int i2 = i + 1;
        this.byteCount = i2;
        if (i2 == this.f779s) {
            this.byteCount = 0;
            generateCRT();
        }
        return b2;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/GCTR";
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int getBlockSize() {
        return this.f779s;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        BlockCipher blockCipher;
        if (!(cipherParameters instanceof ParametersWithIV)) {
            initArrays();
            if (cipherParameters != null) {
                blockCipher = this.cipher;
                blockCipher.init(true, cipherParameters);
            }
            this.initialized = true;
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        initArrays();
        byte[] clone = Arrays.clone(parametersWithIV.getIV());
        this.f778IV = clone;
        if (clone.length != this.blockSize / 2) {
            throw new IllegalArgumentException("Parameter IV length must be == blockSize/2");
        }
        System.arraycopy(clone, 0, this.CTR, 0, clone.length);
        for (int length = this.f778IV.length; length < this.blockSize; length++) {
            this.CTR[length] = 0;
        }
        if (parametersWithIV.getParameters() != null) {
            blockCipher = this.cipher;
            cipherParameters = parametersWithIV.getParameters();
            blockCipher.init(true, cipherParameters);
        }
        this.initialized = true;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public int processBlock(byte[] bArr, int i, byte[] bArr2, int i2) throws DataLengthException, IllegalStateException {
        processBytes(bArr, i, this.f779s, bArr2, i2);
        return this.f779s;
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        if (this.initialized) {
            byte[] bArr = this.f778IV;
            System.arraycopy(bArr, 0, this.CTR, 0, bArr.length);
            for (int length = this.f778IV.length; length < this.blockSize; length++) {
                this.CTR[length] = 0;
            }
            this.byteCount = 0;
            this.cipher.reset();
        }
    }
}