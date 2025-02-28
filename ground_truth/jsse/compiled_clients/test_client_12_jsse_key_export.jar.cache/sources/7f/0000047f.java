package org.bouncycastle.crypto.engines;

import java.math.BigInteger;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSABlindingParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RSABlindingEngine.class */
public class RSABlindingEngine implements AsymmetricBlockCipher {
    private RSACoreEngine core = new RSACoreEngine();
    private RSAKeyParameters key;
    private BigInteger blindingFactor;
    private boolean forEncryption;

    @Override // org.bouncycastle.crypto.AsymmetricBlockCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        RSABlindingParameters rSABlindingParameters = cipherParameters instanceof ParametersWithRandom ? (RSABlindingParameters) ((ParametersWithRandom) cipherParameters).getParameters() : (RSABlindingParameters) cipherParameters;
        this.core.init(z, rSABlindingParameters.getPublicKey());
        this.forEncryption = z;
        this.key = rSABlindingParameters.getPublicKey();
        this.blindingFactor = rSABlindingParameters.getBlindingFactor();
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
        BigInteger convertInput = this.core.convertInput(bArr, i, i2);
        return this.core.convertOutput(this.forEncryption ? blindMessage(convertInput) : unblindMessage(convertInput));
    }

    private BigInteger blindMessage(BigInteger bigInteger) {
        return bigInteger.multiply(this.blindingFactor.modPow(this.key.getExponent(), this.key.getModulus())).mod(this.key.getModulus());
    }

    private BigInteger unblindMessage(BigInteger bigInteger) {
        BigInteger modulus = this.key.getModulus();
        return bigInteger.multiply(BigIntegers.modOddInverse(modulus, this.blindingFactor)).mod(modulus);
    }
}