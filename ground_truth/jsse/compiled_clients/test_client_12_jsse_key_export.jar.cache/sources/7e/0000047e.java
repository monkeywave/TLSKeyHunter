package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RSABlindedEngine.class */
public class RSABlindedEngine implements AsymmetricBlockCipher {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private RSACoreEngine core = new RSACoreEngine();
    private RSAKeyParameters key;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        this.core.init(z, cipherParameters);
        if (!(cipherParameters instanceof ParametersWithRandom)) {
            this.key = (RSAKeyParameters) cipherParameters;
            if (this.key instanceof RSAPrivateCrtKeyParameters) {
                this.random = CryptoServicesRegistrar.getSecureRandom();
                return;
            } else {
                this.random = null;
                return;
            }
        }
        ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
        this.key = (RSAKeyParameters) parametersWithRandom.getParameters();
        if (this.key instanceof RSAPrivateCrtKeyParameters) {
            this.random = parametersWithRandom.getRandom();
        } else {
            this.random = null;
        }
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getInputBlockSize() {
        return this.core.getInputBlockSize();
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public int getOutputBlockSize() {
        return this.core.getOutputBlockSize();
    }

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public byte[] processBlock(byte[] bArr, int i, int i2) {
        BigInteger processBlock;
        if (this.key == null) {
            throw new IllegalStateException("RSA engine not initialised");
        }
        BigInteger convertInput = this.core.convertInput(bArr, i, i2);
        if (this.key instanceof RSAPrivateCrtKeyParameters) {
            RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters = (RSAPrivateCrtKeyParameters) this.key;
            BigInteger publicExponent = rSAPrivateCrtKeyParameters.getPublicExponent();
            if (publicExponent != null) {
                BigInteger modulus = rSAPrivateCrtKeyParameters.getModulus();
                BigInteger createRandomInRange = BigIntegers.createRandomInRange(ONE, modulus.subtract(ONE), this.random);
                processBlock = this.core.processBlock(createRandomInRange.modPow(publicExponent, modulus).multiply(convertInput).mod(modulus)).multiply(BigIntegers.modOddInverse(modulus, createRandomInRange)).mod(modulus);
                if (!convertInput.equals(processBlock.modPow(publicExponent, modulus))) {
                    throw new IllegalStateException("RSA engine faulty decryption/signing detected");
                }
            } else {
                processBlock = this.core.processBlock(convertInput);
            }
        } else {
            processBlock = this.core.processBlock(convertInput);
        }
        return this.core.convertOutput(processBlock);
    }
}