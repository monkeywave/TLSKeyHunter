package org.bouncycastle.pqc.crypto.sphincsplus;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusEngine;

/* loaded from: classes2.dex */
public class SPHINCSPlusKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private SPHINCSPlusParameters parameters;
    private SecureRandom random;

    private byte[] sec_rand(int i) {
        byte[] bArr = new byte[i];
        this.random.nextBytes(bArr);
        return bArr;
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        C1404SK c1404sk;
        byte[] sec_rand;
        SPHINCSPlusEngine engine = this.parameters.getEngine();
        if (engine instanceof SPHINCSPlusEngine.HarakaSEngine) {
            byte[] sec_rand2 = sec_rand(engine.f1429N * 3);
            byte[] bArr = new byte[engine.f1429N];
            byte[] bArr2 = new byte[engine.f1429N];
            sec_rand = new byte[engine.f1429N];
            System.arraycopy(sec_rand2, 0, bArr, 0, engine.f1429N);
            System.arraycopy(sec_rand2, engine.f1429N, bArr2, 0, engine.f1429N);
            System.arraycopy(sec_rand2, engine.f1429N << 1, sec_rand, 0, engine.f1429N);
            c1404sk = new C1404SK(bArr, bArr2);
        } else {
            c1404sk = new C1404SK(sec_rand(engine.f1429N), sec_rand(engine.f1429N));
            sec_rand = sec_rand(engine.f1429N);
        }
        engine.init(sec_rand);
        C1403PK c1403pk = new C1403PK(sec_rand, new C1402HT(engine, c1404sk.seed, sec_rand).htPubKey);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new SPHINCSPlusPublicKeyParameters(this.parameters, c1403pk), (AsymmetricKeyParameter) new SPHINCSPlusPrivateKeyParameters(this.parameters, c1404sk, c1403pk));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.random = keyGenerationParameters.getRandom();
        this.parameters = ((SPHINCSPlusKeyGenerationParameters) keyGenerationParameters).getParameters();
    }
}