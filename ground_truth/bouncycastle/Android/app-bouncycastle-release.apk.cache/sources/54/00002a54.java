package org.bouncycastle.pqc.crypto.picnic;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class PicnicKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private PicnicParameters parameters;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        PicnicEngine engine = this.parameters.getEngine();
        byte[] bArr = new byte[engine.getSecretKeySize()];
        byte[] bArr2 = new byte[engine.getPublicKeySize()];
        engine.crypto_sign_keypair(bArr2, bArr, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new PicnicPublicKeyParameters(this.parameters, bArr2), (AsymmetricKeyParameter) new PicnicPrivateKeyParameters(this.parameters, bArr));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.random = keyGenerationParameters.getRandom();
        this.parameters = ((PicnicKeyGenerationParameters) keyGenerationParameters).getParameters();
    }
}