package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.StreamBlockCipher;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/GOFBBlockCipher.class */
public class GOFBBlockCipher extends StreamBlockCipher {

    /* renamed from: IV */
    private byte[] f469IV;
    private byte[] ofbV;
    private byte[] ofbOutV;
    private int byteCount;
    private final int blockSize;
    private final BlockCipher cipher;
    boolean firstStep;

    /* renamed from: N3 */
    int f470N3;

    /* renamed from: N4 */
    int f471N4;

    /* renamed from: C1 */
    static final int f472C1 = 16843012;

    /* renamed from: C2 */
    static final int f473C2 = 16843009;

    public GOFBBlockCipher(BlockCipher blockCipher) {
        super(blockCipher);
        this.firstStep = true;
        this.cipher = blockCipher;
        this.blockSize = blockCipher.getBlockSize();
        if (this.blockSize != 8) {
            throw new IllegalArgumentException("GCTR only for 64 bit block ciphers");
        }
        this.f469IV = new byte[blockCipher.getBlockSize()];
        this.ofbV = new byte[blockCipher.getBlockSize()];
        this.ofbOutV = new byte[blockCipher.getBlockSize()];
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        this.firstStep = true;
        this.f470N3 = 0;
        this.f471N4 = 0;
        if (!(cipherParameters instanceof ParametersWithIV)) {
            reset();
            if (cipherParameters != null) {
                this.cipher.init(true, cipherParameters);
                return;
            }
            return;
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        byte[] iv = parametersWithIV.getIV();
        if (iv.length < this.f469IV.length) {
            System.arraycopy(iv, 0, this.f469IV, this.f469IV.length - iv.length, iv.length);
            for (int i = 0; i < this.f469IV.length - iv.length; i++) {
                this.f469IV[i] = 0;
            }
        } else {
            System.arraycopy(iv, 0, this.f469IV, 0, this.f469IV.length);
        }
        reset();
        if (parametersWithIV.getParameters() != null) {
            this.cipher.init(true, parametersWithIV.getParameters());
        }
    }

    @Override // org.bouncycastle.crypto.BlockCipher
    public String getAlgorithmName() {
        return this.cipher.getAlgorithmName() + "/GCTR";
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

    @Override // org.bouncycastle.crypto.BlockCipher
    public void reset() {
        this.firstStep = true;
        this.f470N3 = 0;
        this.f471N4 = 0;
        System.arraycopy(this.f469IV, 0, this.ofbV, 0, this.f469IV.length);
        this.byteCount = 0;
        this.cipher.reset();
    }

    private int bytesToint(byte[] bArr, int i) {
        return ((bArr[i + 3] << 24) & (-16777216)) + ((bArr[i + 2] << 16) & 16711680) + ((bArr[i + 1] << 8) & 65280) + (bArr[i] & 255);
    }

    private void intTobytes(int i, byte[] bArr, int i2) {
        bArr[i2 + 3] = (byte) (i >>> 24);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2] = (byte) i;
    }

    @Override // org.bouncycastle.crypto.StreamBlockCipher
    protected byte calculateByte(byte b) {
        if (this.byteCount == 0) {
            if (this.firstStep) {
                this.firstStep = false;
                this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
                this.f470N3 = bytesToint(this.ofbOutV, 0);
                this.f471N4 = bytesToint(this.ofbOutV, 4);
            }
            this.f470N3 += f473C2;
            this.f471N4 += f472C1;
            if (this.f471N4 < f472C1 && this.f471N4 > 0) {
                this.f471N4++;
            }
            intTobytes(this.f470N3, this.ofbV, 0);
            intTobytes(this.f471N4, this.ofbV, 4);
            this.cipher.processBlock(this.ofbV, 0, this.ofbOutV, 0);
        }
        byte[] bArr = this.ofbOutV;
        int i = this.byteCount;
        this.byteCount = i + 1;
        byte b2 = (byte) (bArr[i] ^ b);
        if (this.byteCount == this.blockSize) {
            this.byteCount = 0;
            System.arraycopy(this.ofbV, this.blockSize, this.ofbV, 0, this.ofbV.length - this.blockSize);
            System.arraycopy(this.ofbOutV, 0, this.ofbV, this.ofbV.length - this.blockSize, this.blockSize);
        }
        return b2;
    }
}