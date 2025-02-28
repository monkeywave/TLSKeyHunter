package org.bouncycastle.crypto.modes;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class EAXBlockCipher implements AEADBlockCipher {
    private static final byte cTAG = 2;
    private static final byte hTAG = 1;
    private static final byte nTAG = 0;
    private byte[] associatedTextMac;
    private int blockSize;
    private byte[] bufBlock;
    private int bufOff;
    private CTRModeCipher cipher;
    private boolean cipherInitialized;
    private boolean forEncryption;
    private byte[] initialAssociatedText;
    private Mac mac;
    private byte[] macBlock;
    private int macSize;
    private byte[] nonceMac;

    public EAXBlockCipher(BlockCipher blockCipher) {
        this.blockSize = blockCipher.getBlockSize();
        CMac cMac = new CMac(blockCipher);
        this.mac = cMac;
        this.macBlock = new byte[this.blockSize];
        this.associatedTextMac = new byte[cMac.getMacSize()];
        this.nonceMac = new byte[this.mac.getMacSize()];
        this.cipher = SICBlockCipher.newInstance(blockCipher);
    }

    private void calculateMac() {
        byte[] bArr = new byte[this.blockSize];
        int i = 0;
        this.mac.doFinal(bArr, 0);
        while (true) {
            byte[] bArr2 = this.macBlock;
            if (i >= bArr2.length) {
                return;
            }
            bArr2[i] = (byte) ((this.nonceMac[i] ^ this.associatedTextMac[i]) ^ bArr[i]);
            i++;
        }
    }

    private void initCipher() {
        if (this.cipherInitialized) {
            return;
        }
        this.cipherInitialized = true;
        this.mac.doFinal(this.associatedTextMac, 0);
        int i = this.blockSize;
        byte[] bArr = new byte[i];
        bArr[i - 1] = 2;
        this.mac.update(bArr, 0, i);
    }

    private int process(byte b, byte[] bArr, int i) {
        int processBlock;
        byte[] bArr2 = this.bufBlock;
        int i2 = this.bufOff;
        int i3 = i2 + 1;
        this.bufOff = i3;
        bArr2[i2] = b;
        if (i3 == bArr2.length) {
            int length = bArr.length;
            int i4 = this.blockSize;
            if (length >= i + i4) {
                if (this.forEncryption) {
                    processBlock = this.cipher.processBlock(bArr2, 0, bArr, i);
                    this.mac.update(bArr, i, this.blockSize);
                } else {
                    this.mac.update(bArr2, 0, i4);
                    processBlock = this.cipher.processBlock(this.bufBlock, 0, bArr, i);
                }
                this.bufOff = 0;
                if (!this.forEncryption) {
                    byte[] bArr3 = this.bufBlock;
                    System.arraycopy(bArr3, this.blockSize, bArr3, 0, this.macSize);
                    this.bufOff = this.macSize;
                }
                return processBlock;
            }
            throw new OutputLengthException("Output buffer is too short");
        }
        return 0;
    }

    private void reset(boolean z) {
        this.cipher.reset();
        this.mac.reset();
        this.bufOff = 0;
        Arrays.fill(this.bufBlock, (byte) 0);
        if (z) {
            Arrays.fill(this.macBlock, (byte) 0);
        }
        int i = this.blockSize;
        byte[] bArr = new byte[i];
        bArr[i - 1] = 1;
        this.mac.update(bArr, 0, i);
        this.cipherInitialized = false;
        byte[] bArr2 = this.initialAssociatedText;
        if (bArr2 != null) {
            processAADBytes(bArr2, 0, bArr2.length);
        }
    }

    private boolean verifyMac(byte[] bArr, int i) {
        int i2 = 0;
        for (int i3 = 0; i3 < this.macSize; i3++) {
            i2 |= this.macBlock[i3] ^ bArr[i + i3];
        }
        return i2 == 0;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        initCipher();
        int i2 = this.bufOff;
        byte[] bArr2 = this.bufBlock;
        byte[] bArr3 = new byte[bArr2.length];
        this.bufOff = 0;
        if (this.forEncryption) {
            int i3 = i + i2;
            if (bArr.length >= this.macSize + i3) {
                this.cipher.processBlock(bArr2, 0, bArr3, 0);
                System.arraycopy(bArr3, 0, bArr, i, i2);
                this.mac.update(bArr3, 0, i2);
                calculateMac();
                System.arraycopy(this.macBlock, 0, bArr, i3, this.macSize);
                reset(false);
                return i2 + this.macSize;
            }
            throw new OutputLengthException("Output buffer too short");
        }
        int i4 = this.macSize;
        if (i2 >= i4) {
            if (bArr.length >= (i + i2) - i4) {
                if (i2 > i4) {
                    this.mac.update(bArr2, 0, i2 - i4);
                    this.cipher.processBlock(this.bufBlock, 0, bArr3, 0);
                    System.arraycopy(bArr3, 0, bArr, i, i2 - this.macSize);
                }
                calculateMac();
                if (verifyMac(this.bufBlock, i2 - this.macSize)) {
                    reset(false);
                    return i2 - this.macSize;
                }
                throw new InvalidCipherTextException("mac check in EAX failed");
            }
            throw new OutputLengthException("Output buffer too short");
        }
        throw new InvalidCipherTextException("data too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.cipher.getUnderlyingCipher().getAlgorithmName() + "/EAX";
    }

    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        int i = this.macSize;
        byte[] bArr = new byte[i];
        System.arraycopy(this.macBlock, 0, bArr, 0, i);
        return bArr;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getOutputSize(int i) {
        int i2 = i + this.bufOff;
        if (this.forEncryption) {
            return i2 + this.macSize;
        }
        int i3 = this.macSize;
        if (i2 < i3) {
            return 0;
        }
        return i2 - i3;
    }

    @Override // org.bouncycastle.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.cipher.getUnderlyingCipher();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int i) {
        int i2 = i + this.bufOff;
        if (!this.forEncryption) {
            int i3 = this.macSize;
            if (i2 < i3) {
                return 0;
            }
            i2 -= i3;
        }
        return i2 - (i2 % this.blockSize);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        byte[] iv;
        CipherParameters parameters;
        this.forEncryption = z;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            iv = aEADParameters.getNonce();
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            this.macSize = aEADParameters.getMacSize() / 8;
            parameters = aEADParameters.getKey();
        } else if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("invalid parameters passed to EAX");
        } else {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            iv = parametersWithIV.getIV();
            this.initialAssociatedText = null;
            this.macSize = this.mac.getMacSize() / 2;
            parameters = parametersWithIV.getParameters();
        }
        this.bufBlock = new byte[z ? this.blockSize : this.blockSize + this.macSize];
        byte[] bArr = new byte[this.blockSize];
        this.mac.init(parameters);
        int i = this.blockSize;
        bArr[i - 1] = 0;
        this.mac.update(bArr, 0, i);
        this.mac.update(iv, 0, iv.length);
        this.mac.doFinal(this.nonceMac, 0);
        this.cipher.init(true, new ParametersWithIV(parameters, this.nonceMac));
        reset();
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        this.mac.update(b);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        if (this.cipherInitialized) {
            throw new IllegalStateException("AAD data cannot be added after encryption/decryption processing has begun.");
        }
        this.mac.update(bArr, i, i2);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException {
        initCipher();
        return process(b, bArr, i);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException {
        initCipher();
        if (bArr.length >= i + i2) {
            int i4 = 0;
            for (int i5 = 0; i5 != i2; i5++) {
                i4 += process(bArr[i + i5], bArr2, i3 + i4);
            }
            return i4;
        }
        throw new DataLengthException("Input buffer too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        reset(true);
    }
}