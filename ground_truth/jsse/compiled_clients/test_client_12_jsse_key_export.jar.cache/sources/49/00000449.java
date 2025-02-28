package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/encodings/PKCS1Encoding.class */
public class PKCS1Encoding implements AsymmetricBlockCipher {
    public static final String STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.strict";
    public static final String NOT_STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.not_strict";
    private static final int HEADER_LENGTH = 10;
    private SecureRandom random;
    private AsymmetricBlockCipher engine;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private boolean useStrictLength;
    private int pLen;
    private byte[] fallback;
    private byte[] blockBuffer;

    public PKCS1Encoding(AsymmetricBlockCipher asymmetricBlockCipher) {
        this.pLen = -1;
        this.fallback = null;
        this.engine = asymmetricBlockCipher;
        this.useStrictLength = useStrict();
    }

    public PKCS1Encoding(AsymmetricBlockCipher asymmetricBlockCipher, int i) {
        this.pLen = -1;
        this.fallback = null;
        this.engine = asymmetricBlockCipher;
        this.useStrictLength = useStrict();
        this.pLen = i;
    }

    public PKCS1Encoding(AsymmetricBlockCipher asymmetricBlockCipher, byte[] bArr) {
        this.pLen = -1;
        this.fallback = null;
        this.engine = asymmetricBlockCipher;
        this.useStrictLength = useStrict();
        this.fallback = bArr;
        this.pLen = bArr.length;
    }

    private boolean useStrict() {
        return (Properties.isOverrideSetTo(NOT_STRICT_LENGTH_ENABLED_PROPERTY, true) || Properties.isOverrideSetTo(STRICT_LENGTH_ENABLED_PROPERTY, false)) ? false : true;
    }

    public AsymmetricBlockCipher getUnderlyingCipher() {
        return this.engine;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        AsymmetricKeyParameter asymmetricKeyParameter;
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            asymmetricKeyParameter = (AsymmetricKeyParameter) parametersWithRandom.getParameters();
        } else {
            asymmetricKeyParameter = (AsymmetricKeyParameter) cipherParameters;
            if (!asymmetricKeyParameter.isPrivate() && z) {
                this.random = CryptoServicesRegistrar.getSecureRandom();
            }
        }
        this.engine.init(z, cipherParameters);
        this.forPrivateKey = asymmetricKeyParameter.isPrivate();
        this.forEncryption = z;
        this.blockBuffer = new byte[this.engine.getOutputBlockSize()];
        if (this.pLen > 0 && this.fallback == null && this.random == null) {
            throw new IllegalArgumentException("encoder requires random");
        }
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        int inputBlockSize = this.engine.getInputBlockSize();
        return this.forEncryption ? inputBlockSize - 10 : inputBlockSize;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        int outputBlockSize = this.engine.getOutputBlockSize();
        return this.forEncryption ? outputBlockSize : outputBlockSize - 10;
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }

    private byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (i2 > getInputBlockSize()) {
            throw new IllegalArgumentException("input data too large");
        }
        byte[] bArr2 = new byte[this.engine.getInputBlockSize()];
        if (this.forPrivateKey) {
            bArr2[0] = 1;
            for (int i3 = 1; i3 != (bArr2.length - i2) - 1; i3++) {
                bArr2[i3] = -1;
            }
        } else {
            this.random.nextBytes(bArr2);
            bArr2[0] = 2;
            for (int i4 = 1; i4 != (bArr2.length - i2) - 1; i4++) {
                while (bArr2[i4] == 0) {
                    bArr2[i4] = (byte) this.random.nextInt();
                }
            }
        }
        bArr2[(bArr2.length - i2) - 1] = 0;
        System.arraycopy(bArr, i, bArr2, bArr2.length - i2, i2);
        return this.engine.processBlock(bArr2, 0, bArr2.length);
    }

    private static int checkPkcs1Encoding(byte[] bArr, int i) {
        byte b = 0 | (bArr[0] ^ 2);
        int length = bArr.length - (i + 1);
        for (int i2 = 1; i2 < length; i2++) {
            byte b2 = bArr[i2];
            int i3 = b2 | (b2 >> 1);
            int i4 = i3 | (i3 >> 2);
            b |= ((i4 | (i4 >> 4)) & 1) - 1;
        }
        int i5 = b | bArr[bArr.length - (i + 1)];
        int i6 = i5 | (i5 >> 1);
        int i7 = i6 | (i6 >> 2);
        return (((i7 | (i7 >> 4)) & 1) - 1) ^ (-1);
    }

    private byte[] decodeBlockOrRandom(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        byte[] bArr2;
        if (this.forPrivateKey) {
            byte[] processBlock = this.engine.processBlock(bArr, i, i2);
            if (this.fallback == null) {
                bArr2 = new byte[this.pLen];
                this.random.nextBytes(bArr2);
            } else {
                bArr2 = this.fallback;
            }
            byte[] bArr3 = this.useStrictLength & (processBlock.length != this.engine.getOutputBlockSize()) ? this.blockBuffer : processBlock;
            int checkPkcs1Encoding = checkPkcs1Encoding(bArr3, this.pLen);
            byte[] bArr4 = new byte[this.pLen];
            for (int i3 = 0; i3 < this.pLen; i3++) {
                bArr4[i3] = (byte) ((bArr3[i3 + (bArr3.length - this.pLen)] & (checkPkcs1Encoding ^ (-1))) | (bArr2[i3] & checkPkcs1Encoding));
            }
            Arrays.fill(bArr3, (byte) 0);
            return bArr4;
        }
        throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");
    }

    private byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        boolean z;
        if (this.pLen != -1) {
            return decodeBlockOrRandom(bArr, i, i2);
        }
        byte[] processBlock = this.engine.processBlock(bArr, i, i2);
        boolean z2 = this.useStrictLength & (processBlock.length != this.engine.getOutputBlockSize());
        byte[] bArr2 = processBlock.length < getOutputBlockSize() ? this.blockBuffer : processBlock;
        byte b = bArr2[0];
        if (this.forPrivateKey) {
            z = b != 2;
        } else {
            z = b != 1;
        }
        int findStart = findStart(b, bArr2) + 1;
        if (z || (findStart < 10)) {
            Arrays.fill(bArr2, (byte) 0);
            throw new InvalidCipherTextException("block incorrect");
        } else if (z2) {
            Arrays.fill(bArr2, (byte) 0);
            throw new InvalidCipherTextException("block incorrect size");
        } else {
            byte[] bArr3 = new byte[bArr2.length - findStart];
            System.arraycopy(bArr2, findStart, bArr3, 0, bArr3.length);
            return bArr3;
        }
    }

    private int findStart(byte b, byte[] bArr) throws InvalidCipherTextException {
        int i = -1;
        boolean z = false;
        for (int i2 = 1; i2 != bArr.length; i2++) {
            byte b2 = bArr[i2];
            if ((b2 == 0) & (i < 0)) {
                i = i2;
            }
            z |= (b == 1) & (i < 0) & (b2 != -1);
        }
        if (z) {
            return -1;
        }
        return i;
    }
}