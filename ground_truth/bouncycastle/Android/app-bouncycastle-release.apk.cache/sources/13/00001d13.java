package org.bouncycastle.crypto.encodings;

import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Properties;

/* loaded from: classes2.dex */
public class PKCS1Encoding implements AsymmetricBlockCipher {
    private static final int HEADER_LENGTH = 10;
    public static final String NOT_STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.not_strict";
    public static final String STRICT_LENGTH_ENABLED_PROPERTY = "org.bouncycastle.pkcs1.strict";
    private byte[] blockBuffer;
    private AsymmetricBlockCipher engine;
    private byte[] fallback;
    private boolean forEncryption;
    private boolean forPrivateKey;
    private int pLen;
    private SecureRandom random;
    private boolean useStrictLength;

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

    private static int checkPkcs1Encoding1(byte[] bArr) {
        int i = 0;
        int i2 = -((bArr[0] & UByte.MAX_VALUE) ^ 1);
        int i3 = 0;
        for (int i4 = 1; i4 < bArr.length; i4++) {
            int i5 = bArr[i4] & UByte.MAX_VALUE;
            int i6 = (i5 - 1) >> 31;
            i ^= ((~i3) & i4) & i6;
            i3 |= i6;
            i2 |= ~((((i5 ^ 255) - 1) >> 31) | i3);
        }
        return ((bArr.length - 1) - i) | (((i - 9) | i2) >> 31);
    }

    private static int checkPkcs1Encoding2(byte[] bArr) {
        int i = 0;
        int i2 = -((bArr[0] & UByte.MAX_VALUE) ^ 2);
        int i3 = 0;
        for (int i4 = 1; i4 < bArr.length; i4++) {
            int i5 = ((bArr[i4] & UByte.MAX_VALUE) - 1) >> 31;
            i ^= ((~i3) & i4) & i5;
            i3 |= i5;
        }
        return ((bArr.length - 1) - i) | ((i2 | (i - 9)) >> 31);
    }

    private static int checkPkcs1Encoding2(byte[] bArr, int i) {
        int length = (bArr.length - 1) - i;
        int i2 = (length - 9) | (-((bArr[0] & 255) ^ 2));
        for (int i3 = 1; i3 < length; i3++) {
            i2 |= (bArr[i3] & 255) - 1;
        }
        return ((-(bArr[length] & 255)) | i2) >> 31;
    }

    private byte[] decodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (!this.forPrivateKey || this.pLen == -1) {
            int outputBlockSize = this.engine.getOutputBlockSize();
            byte[] processBlock = this.engine.processBlock(bArr, i, i2);
            boolean z = this.useStrictLength & (processBlock.length != outputBlockSize);
            byte[] bArr2 = processBlock.length < outputBlockSize ? this.blockBuffer : processBlock;
            int checkPkcs1Encoding2 = this.forPrivateKey ? checkPkcs1Encoding2(bArr2) : checkPkcs1Encoding1(bArr2);
            try {
                if (checkPkcs1Encoding2 >= 0) {
                    if (z) {
                        throw new InvalidCipherTextException("block incorrect size");
                    }
                    byte[] bArr3 = new byte[checkPkcs1Encoding2];
                    System.arraycopy(bArr2, bArr2.length - checkPkcs1Encoding2, bArr3, 0, checkPkcs1Encoding2);
                    return bArr3;
                }
                throw new InvalidCipherTextException("block incorrect");
            } finally {
                Arrays.fill(processBlock, (byte) 0);
                byte[] bArr4 = this.blockBuffer;
                Arrays.fill(bArr4, 0, Math.max(0, bArr4.length - processBlock.length), (byte) 0);
            }
        }
        return decodeBlockOrRandom(bArr, i, i2);
    }

    private byte[] decodeBlockOrRandom(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (this.forPrivateKey) {
            int i3 = this.pLen;
            byte[] bArr2 = this.fallback;
            if (bArr2 == null) {
                bArr2 = new byte[i3];
                this.random.nextBytes(bArr2);
            }
            int outputBlockSize = this.engine.getOutputBlockSize();
            byte[] processBlock = this.engine.processBlock(bArr, i, i2);
            byte[] bArr3 = (processBlock.length == outputBlockSize || (!this.useStrictLength && processBlock.length >= outputBlockSize)) ? processBlock : this.blockBuffer;
            int checkPkcs1Encoding2 = checkPkcs1Encoding2(bArr3, i3);
            int length = bArr3.length - i3;
            byte[] bArr4 = new byte[i3];
            for (int i4 = 0; i4 < i3; i4++) {
                bArr4[i4] = (byte) ((bArr3[length + i4] & (~checkPkcs1Encoding2)) | (bArr2[i4] & checkPkcs1Encoding2));
            }
            Arrays.fill(processBlock, (byte) 0);
            byte[] bArr5 = this.blockBuffer;
            Arrays.fill(bArr5, 0, Math.max(0, bArr5.length - processBlock.length), (byte) 0);
            return bArr4;
        }
        throw new InvalidCipherTextException("sorry, this method is only for decryption, not for signing");
    }

    private byte[] encodeBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        if (i2 <= getInputBlockSize()) {
            int inputBlockSize = this.engine.getInputBlockSize();
            byte[] bArr2 = new byte[inputBlockSize];
            if (this.forPrivateKey) {
                bArr2[0] = 1;
                for (int i3 = 1; i3 != (inputBlockSize - i2) - 1; i3++) {
                    bArr2[i3] = -1;
                }
            } else {
                this.random.nextBytes(bArr2);
                bArr2[0] = 2;
                for (int i4 = 1; i4 != (inputBlockSize - i2) - 1; i4++) {
                    while (bArr2[i4] == 0) {
                        bArr2[i4] = (byte) this.random.nextInt();
                    }
                }
            }
            int i5 = inputBlockSize - i2;
            bArr2[i5 - 1] = 0;
            System.arraycopy(bArr, i, bArr2, i5, i2);
            return this.engine.processBlock(bArr2, 0, inputBlockSize);
        }
        throw new IllegalArgumentException("input data too large");
    }

    private boolean useStrict() {
        if (Properties.isOverrideSetTo(NOT_STRICT_LENGTH_ENABLED_PROPERTY, true)) {
            return false;
        }
        return !Properties.isOverrideSetTo(STRICT_LENGTH_ENABLED_PROPERTY, false);
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
    public byte[] processBlock(byte[] bArr, int i, int i2) throws InvalidCipherTextException {
        return this.forEncryption ? encodeBlock(bArr, i, i2) : decodeBlock(bArr, i, i2);
    }
}