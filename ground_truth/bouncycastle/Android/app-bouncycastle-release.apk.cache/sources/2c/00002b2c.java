package org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;

/* loaded from: classes2.dex */
public class XWingKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SecureRandom random;

    private AsymmetricCipherKeyPair genKeyPair() {
        MLKEMKeyPairGenerator mLKEMKeyPairGenerator = new MLKEMKeyPairGenerator();
        mLKEMKeyPairGenerator.init(new MLKEMKeyGenerationParameters(this.random, MLKEMParameters.ml_kem_768));
        X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
        x25519KeyPairGenerator.init(new X25519KeyGenerationParameters(this.random));
        AsymmetricCipherKeyPair generateKeyPair = mLKEMKeyPairGenerator.generateKeyPair();
        AsymmetricCipherKeyPair generateKeyPair2 = x25519KeyPairGenerator.generateKeyPair();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new XWingPublicKeyParameters(generateKeyPair.getPublic(), generateKeyPair2.getPublic()), (AsymmetricKeyParameter) new XWingPrivateKeyParameters(generateKeyPair.getPrivate(), generateKeyPair2.getPrivate()));
    }

    private void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.random = keyGenerationParameters.getRandom();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }
}