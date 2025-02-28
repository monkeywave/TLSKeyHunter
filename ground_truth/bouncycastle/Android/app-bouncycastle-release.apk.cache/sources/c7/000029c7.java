package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class HQCKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private int N_BYTE;
    private int delta;
    private HQCKeyGenerationParameters hqcKeyGenerationParameters;

    /* renamed from: k */
    private int f1300k;

    /* renamed from: n */
    private int f1301n;
    private SecureRandom random;

    /* renamed from: w */
    private int f1302w;

    /* renamed from: we */
    private int f1303we;

    /* renamed from: wr */
    private int f1304wr;

    private AsymmetricCipherKeyPair genKeyPair(byte[] bArr) {
        HQCEngine engine = this.hqcKeyGenerationParameters.getParameters().getEngine();
        int i = this.N_BYTE;
        byte[] bArr2 = new byte[i + 40];
        byte[] bArr3 = new byte[i + 80];
        engine.genKeyPair(bArr2, bArr3, bArr);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new HQCPublicKeyParameters(this.hqcKeyGenerationParameters.getParameters(), bArr2), (AsymmetricKeyParameter) new HQCPrivateKeyParameters(this.hqcKeyGenerationParameters.getParameters(), bArr3));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        byte[] bArr = new byte[48];
        this.random.nextBytes(bArr);
        return genKeyPair(bArr);
    }

    public AsymmetricCipherKeyPair generateKeyPairWithSeed(byte[] bArr) {
        return genKeyPair(bArr);
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.hqcKeyGenerationParameters = (HQCKeyGenerationParameters) keyGenerationParameters;
        this.random = keyGenerationParameters.getRandom();
        this.f1301n = this.hqcKeyGenerationParameters.getParameters().getN();
        this.f1300k = this.hqcKeyGenerationParameters.getParameters().getK();
        this.delta = this.hqcKeyGenerationParameters.getParameters().getDelta();
        this.f1302w = this.hqcKeyGenerationParameters.getParameters().getW();
        this.f1304wr = this.hqcKeyGenerationParameters.getParameters().getWr();
        this.f1303we = this.hqcKeyGenerationParameters.getParameters().getWe();
        this.N_BYTE = (this.f1301n + 7) / 8;
    }
}