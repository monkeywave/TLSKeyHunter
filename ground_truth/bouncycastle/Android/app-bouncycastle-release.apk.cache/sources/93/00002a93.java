package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class SLHDSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SLHDSAParameters parameters;
    private SecureRandom random;

    private AsymmetricCipherKeyPair implGenerateKeyPair(SLHDSAEngine sLHDSAEngine, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        C1401SK c1401sk = new C1401SK(bArr, bArr2);
        sLHDSAEngine.init(bArr3);
        C1400PK c1400pk = new C1400PK(bArr3, new C1399HT(sLHDSAEngine, c1401sk.seed, bArr3).htPubKey);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new SLHDSAPublicKeyParameters(this.parameters, c1400pk), (AsymmetricKeyParameter) new SLHDSAPrivateKeyParameters(this.parameters, c1401sk, c1400pk));
    }

    private byte[] sec_rand(int i) {
        byte[] bArr = new byte[i];
        this.random.nextBytes(bArr);
        return bArr;
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        SLHDSAEngine engine = this.parameters.getEngine();
        return implGenerateKeyPair(engine, sec_rand(engine.f1404N), sec_rand(engine.f1404N), sec_rand(engine.f1404N));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.random = keyGenerationParameters.getRandom();
        this.parameters = ((SLHDSAKeyGenerationParameters) keyGenerationParameters).getParameters();
    }

    public AsymmetricCipherKeyPair internalGenerateKeyPair(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return implGenerateKeyPair(this.parameters.getEngine(), bArr, bArr2, bArr3);
    }
}