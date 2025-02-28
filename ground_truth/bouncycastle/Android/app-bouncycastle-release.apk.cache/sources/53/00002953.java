package org.bouncycastle.pqc.crypto.bike;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class BIKEKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private int L_BYTE;
    private int R_BYTE;
    private BIKEKeyGenerationParameters bikeKeyGenerationParameters;

    /* renamed from: l */
    private int f1209l;

    /* renamed from: r */
    private int f1210r;
    private SecureRandom random;

    private AsymmetricCipherKeyPair genKeyPair() {
        BIKEEngine engine = this.bikeKeyGenerationParameters.getParameters().getEngine();
        int i = this.R_BYTE;
        byte[] bArr = new byte[i];
        byte[] bArr2 = new byte[i];
        byte[] bArr3 = new byte[i];
        byte[] bArr4 = new byte[this.L_BYTE];
        engine.genKeyPair(bArr, bArr2, bArr4, bArr3, this.random);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new BIKEPublicKeyParameters(this.bikeKeyGenerationParameters.getParameters(), bArr3), (AsymmetricKeyParameter) new BIKEPrivateKeyParameters(this.bikeKeyGenerationParameters.getParameters(), bArr, bArr2, bArr4));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.bikeKeyGenerationParameters = (BIKEKeyGenerationParameters) keyGenerationParameters;
        this.random = keyGenerationParameters.getRandom();
        this.f1210r = this.bikeKeyGenerationParameters.getParameters().getR();
        int l = this.bikeKeyGenerationParameters.getParameters().getL();
        this.f1209l = l;
        this.L_BYTE = l / 8;
        this.R_BYTE = (this.f1210r + 7) / 8;
    }
}