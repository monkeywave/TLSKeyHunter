package org.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class FrodoKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {

    /* renamed from: B */
    private int f1255B;

    /* renamed from: D */
    private int f1256D;
    private FrodoKeyGenerationParameters frodoParams;

    /* renamed from: n */
    private int f1257n;
    private SecureRandom random;

    private AsymmetricCipherKeyPair genKeyPair() {
        FrodoEngine engine = this.frodoParams.getParameters().getEngine();
        byte[] bArr = new byte[engine.getPrivateKeySize()];
        byte[] bArr2 = new byte[engine.getPublicKeySize()];
        engine.kem_keypair(bArr2, bArr, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new FrodoPublicKeyParameters(this.frodoParams.getParameters(), bArr2), (AsymmetricKeyParameter) new FrodoPrivateKeyParameters(this.frodoParams.getParameters(), bArr));
    }

    private void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.frodoParams = (FrodoKeyGenerationParameters) keyGenerationParameters;
        this.random = keyGenerationParameters.getRandom();
        this.f1257n = this.frodoParams.getParameters().getN();
        this.f1256D = this.frodoParams.getParameters().getD();
        this.f1255B = this.frodoParams.getParameters().getB();
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