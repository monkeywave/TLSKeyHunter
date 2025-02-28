package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class LMSKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    LMSKeyGenerationParameters param;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        SecureRandom random = this.param.getRandom();
        byte[] bArr = new byte[16];
        random.nextBytes(bArr);
        LMSigParameters lMSigParam = this.param.getParameters().getLMSigParam();
        byte[] bArr2 = new byte[lMSigParam.getM()];
        random.nextBytes(bArr2);
        LMSPrivateKeyParameters generateKeys = LMS.generateKeys(lMSigParam, this.param.getParameters().getLMOTSParam(), 0, bArr, bArr2);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) generateKeys.getPublicKey(), (AsymmetricKeyParameter) generateKeys);
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (LMSKeyGenerationParameters) keyGenerationParameters;
    }
}