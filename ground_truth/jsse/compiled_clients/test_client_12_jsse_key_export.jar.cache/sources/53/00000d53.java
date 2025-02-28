package org.bouncycastle.pqc.crypto.lms;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/lms/HSSKeyPairGenerator.class */
public class HSSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    HSSKeyGenerationParameters param;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (HSSKeyGenerationParameters) keyGenerationParameters;
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        HSSPrivateKeyParameters generateHSSKeyPair = HSS.generateHSSKeyPair(this.param);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) generateHSSKeyPair.getPublicKey(), (AsymmetricKeyParameter) generateHSSKeyPair);
    }
}