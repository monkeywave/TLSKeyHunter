package org.bouncycastle.pqc.jcajce.provider.mceliece;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.pqc.jcajce.spec.McElieceKeyGenParameterSpec;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceKeyGenerationParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceKeyPairGenerator;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McElieceParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePrivateKeyParameters;
import org.bouncycastle.pqc.legacy.crypto.mceliece.McEliecePublicKeyParameters;

/* loaded from: classes2.dex */
public class McElieceKeyPairGeneratorSpi extends KeyPairGenerator {
    McElieceKeyPairGenerator kpg;

    public McElieceKeyPairGeneratorSpi() {
        super("McEliece");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair generateKeyPair = this.kpg.generateKeyPair();
        return new KeyPair(new BCMcEliecePublicKey((McEliecePublicKeyParameters) generateKeyPair.getPublic()), new BCMcEliecePrivateKey((McEliecePrivateKeyParameters) generateKeyPair.getPrivate()));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        try {
            initialize(new McElieceKeyGenParameterSpec(), secureRandom);
        } catch (InvalidAlgorithmParameterException unused) {
        }
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.kpg = new McElieceKeyPairGenerator();
        McElieceKeyGenParameterSpec mcElieceKeyGenParameterSpec = (McElieceKeyGenParameterSpec) algorithmParameterSpec;
        this.kpg.init(new McElieceKeyGenerationParameters(secureRandom, new McElieceParameters(mcElieceKeyGenParameterSpec.getM(), mcElieceKeyGenParameterSpec.getT())));
    }
}