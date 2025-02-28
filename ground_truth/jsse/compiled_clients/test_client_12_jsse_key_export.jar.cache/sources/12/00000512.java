package org.bouncycastle.crypto.modes;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.modes.kgcm.KGCMMultiplier;
import org.bouncycastle.crypto.modes.kgcm.Tables16kKGCMMultiplier_512;
import org.bouncycastle.crypto.modes.kgcm.Tables4kKGCMMultiplier_128;
import org.bouncycastle.crypto.modes.kgcm.Tables8kKGCMMultiplier_256;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/KGCMBlockCipher.class */
public class KGCMBlockCipher implements AEADBlockCipher {
    private static final int MIN_MAC_BITS = 64;
    private BlockCipher engine;
    private BufferedBlockCipher ctrEngine;
    private boolean forEncryption;
    private byte[] initialAssociatedText;

    /* renamed from: iv */
    private byte[] f477iv;
    private KGCMMultiplier multiplier;

    /* renamed from: b */
    private long[] f478b;
    private final int blockSize;
    private ExposedByteArrayOutputStream associatedText = new ExposedByteArrayOutputStream();
    private ExposedByteArrayOutputStream data = new ExposedByteArrayOutputStream();
    private int macSize = -1;
    private byte[] macBlock = null;

    /* JADX INFO: Access modifiers changed from: private */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/modes/KGCMBlockCipher$ExposedByteArrayOutputStream.class */
    public class ExposedByteArrayOutputStream extends ByteArrayOutputStream {
        public ExposedByteArrayOutputStream() {
        }

        public byte[] getBuffer() {
            return this.buf;
        }
    }

    private static KGCMMultiplier createDefaultMultiplier(int i) {
        switch (i) {
            case 16:
                return new Tables4kKGCMMultiplier_128();
            case 32:
                return new Tables8kKGCMMultiplier_256();
            case 64:
                return new Tables16kKGCMMultiplier_512();
            default:
                throw new IllegalArgumentException("Only 128, 256, and 512 -bit block sizes supported");
        }
    }

    public KGCMBlockCipher(BlockCipher blockCipher) {
        this.engine = blockCipher;
        this.ctrEngine = new BufferedBlockCipher(new KCTRBlockCipher(this.engine));
        this.blockSize = this.engine.getBlockSize();
        this.initialAssociatedText = new byte[this.blockSize];
        this.f477iv = new byte[this.blockSize];
        this.multiplier = createDefaultMultiplier(this.blockSize);
        this.f478b = new long[this.blockSize >>> 3];
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void init(boolean z, CipherParameters cipherParameters) throws IllegalArgumentException {
        KeyParameter keyParameter;
        this.forEncryption = z;
        if (cipherParameters instanceof AEADParameters) {
            AEADParameters aEADParameters = (AEADParameters) cipherParameters;
            byte[] nonce = aEADParameters.getNonce();
            int length = this.f477iv.length - nonce.length;
            Arrays.fill(this.f477iv, (byte) 0);
            System.arraycopy(nonce, 0, this.f477iv, length, nonce.length);
            this.initialAssociatedText = aEADParameters.getAssociatedText();
            int macSize = aEADParameters.getMacSize();
            if (macSize < 64 || macSize > (this.blockSize << 3) || (macSize & 7) != 0) {
                throw new IllegalArgumentException("Invalid value for MAC size: " + macSize);
            }
            this.macSize = macSize >>> 3;
            keyParameter = aEADParameters.getKey();
            if (this.initialAssociatedText != null) {
                processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
            }
        } else if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("Invalid parameter passed");
        } else {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            byte[] iv = parametersWithIV.getIV();
            int length2 = this.f477iv.length - iv.length;
            Arrays.fill(this.f477iv, (byte) 0);
            System.arraycopy(iv, 0, this.f477iv, length2, iv.length);
            this.initialAssociatedText = null;
            this.macSize = this.blockSize;
            keyParameter = (KeyParameter) parametersWithIV.getParameters();
        }
        this.macBlock = new byte[this.blockSize];
        this.ctrEngine.init(true, new ParametersWithIV(keyParameter, this.f477iv));
        this.engine.init(true, keyParameter);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public String getAlgorithmName() {
        return this.engine.getAlgorithmName() + "/KGCM";
    }

    @Override // org.bouncycastle.crypto.modes.AEADBlockCipher
    public BlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADByte(byte b) {
        this.associatedText.write(b);
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void processAADBytes(byte[] bArr, int i, int i2) {
        this.associatedText.write(bArr, i, i2);
    }

    private void processAAD(byte[] bArr, int i, int i2) {
        int i3 = i;
        int i4 = i + i2;
        while (i3 < i4) {
            xorWithInput(this.f478b, bArr, i3);
            this.multiplier.multiplyH(this.f478b);
            i3 += this.blockSize;
        }
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processByte(byte b, byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        this.data.write(b);
        return 0;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) throws DataLengthException, IllegalStateException {
        if (bArr.length < i + i2) {
            throw new DataLengthException("input buffer too short");
        }
        this.data.write(bArr, i, i2);
        return 0;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int doFinal(byte[] bArr, int i) throws IllegalStateException, InvalidCipherTextException {
        int doFinal;
        int size = this.data.size();
        if (this.forEncryption || size >= this.macSize) {
            byte[] bArr2 = new byte[this.blockSize];
            this.engine.processBlock(bArr2, 0, bArr2, 0);
            long[] jArr = new long[this.blockSize >>> 3];
            Pack.littleEndianToLong(bArr2, 0, jArr);
            this.multiplier.init(jArr);
            Arrays.fill(bArr2, (byte) 0);
            Arrays.fill(jArr, 0L);
            int size2 = this.associatedText.size();
            if (size2 > 0) {
                processAAD(this.associatedText.getBuffer(), 0, size2);
            }
            if (!this.forEncryption) {
                int i2 = size - this.macSize;
                if (bArr.length - i < i2) {
                    throw new OutputLengthException("Output buffer too short");
                }
                calculateMac(this.data.getBuffer(), 0, i2, size2);
                int processBytes = this.ctrEngine.processBytes(this.data.getBuffer(), 0, i2, bArr, i);
                doFinal = processBytes + this.ctrEngine.doFinal(bArr, i + processBytes);
            } else if ((bArr.length - i) - this.macSize < size) {
                throw new OutputLengthException("Output buffer too short");
            } else {
                int processBytes2 = this.ctrEngine.processBytes(this.data.getBuffer(), 0, size, bArr, i);
                doFinal = processBytes2 + this.ctrEngine.doFinal(bArr, i + processBytes2);
                calculateMac(bArr, i, size, size2);
            }
            if (this.macBlock == null) {
                throw new IllegalStateException("mac is not calculated");
            }
            if (this.forEncryption) {
                System.arraycopy(this.macBlock, 0, bArr, i + doFinal, this.macSize);
                reset();
                return doFinal + this.macSize;
            }
            byte[] bArr3 = new byte[this.macSize];
            System.arraycopy(this.data.getBuffer(), size - this.macSize, bArr3, 0, this.macSize);
            byte[] bArr4 = new byte[this.macSize];
            System.arraycopy(this.macBlock, 0, bArr4, 0, this.macSize);
            if (Arrays.constantTimeAreEqual(bArr3, bArr4)) {
                reset();
                return doFinal;
            }
            throw new InvalidCipherTextException("mac verification failed");
        }
        throw new InvalidCipherTextException("data too short");
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public byte[] getMac() {
        byte[] bArr = new byte[this.macSize];
        System.arraycopy(this.macBlock, 0, bArr, 0, this.macSize);
        return bArr;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getUpdateOutputSize(int i) {
        return 0;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public int getOutputSize(int i) {
        int size = i + this.data.size();
        if (this.forEncryption) {
            return size + this.macSize;
        }
        if (size < this.macSize) {
            return 0;
        }
        return size - this.macSize;
    }

    @Override // org.bouncycastle.crypto.modes.AEADCipher
    public void reset() {
        Arrays.fill(this.f478b, 0L);
        this.engine.reset();
        this.data.reset();
        this.associatedText.reset();
        if (this.initialAssociatedText != null) {
            processAADBytes(this.initialAssociatedText, 0, this.initialAssociatedText.length);
        }
    }

    private void calculateMac(byte[] bArr, int i, int i2, int i3) {
        int i4 = i;
        int i5 = i + i2;
        while (i4 < i5) {
            xorWithInput(this.f478b, bArr, i4);
            this.multiplier.multiplyH(this.f478b);
            i4 += this.blockSize;
        }
        long[] jArr = this.f478b;
        jArr[0] = jArr[0] ^ ((i3 & 4294967295L) << 3);
        long[] jArr2 = this.f478b;
        int i6 = this.blockSize >>> 4;
        jArr2[i6] = jArr2[i6] ^ ((i2 & 4294967295L) << 3);
        this.macBlock = Pack.longToLittleEndian(this.f478b);
        this.engine.processBlock(this.macBlock, 0, this.macBlock, 0);
    }

    private static void xorWithInput(long[] jArr, byte[] bArr, int i) {
        for (int i2 = 0; i2 < jArr.length; i2++) {
            int i3 = i2;
            jArr[i3] = jArr[i3] ^ Pack.littleEndianToLong(bArr, i);
            i += 8;
        }
    }
}