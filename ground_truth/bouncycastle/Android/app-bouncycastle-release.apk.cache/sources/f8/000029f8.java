package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class MLDSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private MLDSAParameters parameters;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        byte[][] generateKeyPair = this.parameters.getEngine(this.random).generateKeyPair();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new MLDSAPublicKeyParameters(this.parameters, generateKeyPair[0], generateKeyPair[6]), (AsymmetricKeyParameter) new MLDSAPrivateKeyParameters(this.parameters, generateKeyPair[0], generateKeyPair[1], generateKeyPair[2], generateKeyPair[3], generateKeyPair[4], generateKeyPair[5], generateKeyPair[6], generateKeyPair[7]));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.parameters = ((MLDSAKeyGenerationParameters) keyGenerationParameters).getParameters();
        this.random = keyGenerationParameters.getRandom();
    }
}