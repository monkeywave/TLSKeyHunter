package org.bouncycastle.pqc.jcajce.provider.kyber;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class KyberKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    MLKEMKeyPairGenerator engine;
    boolean initialised;
    private MLKEMParameters kyberParameters;
    MLKEMKeyGenerationParameters param;
    SecureRandom random;

    /* loaded from: classes2.dex */
    public static class Kyber1024 extends KyberKeyPairGeneratorSpi {
        public Kyber1024() {
            super(MLKEMParameters.ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber512 extends KyberKeyPairGeneratorSpi {
        public Kyber512() {
            super(MLKEMParameters.ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class Kyber768 extends KyberKeyPairGeneratorSpi {
        public Kyber768() {
            super(MLKEMParameters.ml_kem_768);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(KyberParameterSpec.kyber512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(KyberParameterSpec.kyber768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(KyberParameterSpec.kyber1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    public KyberKeyPairGeneratorSpi() {
        super("KYBER");
        this.engine = new MLKEMKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.kyberParameters = null;
    }

    protected KyberKeyPairGeneratorSpi(MLKEMParameters mLKEMParameters) {
        super(Strings.toUpperCase(mLKEMParameters.getName()));
        this.engine = new MLKEMKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.kyberParameters = mLKEMParameters;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof KyberParameterSpec ? ((KyberParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = this.kyberParameters != null ? new MLKEMKeyGenerationParameters(this.random, this.kyberParameters) : new MLKEMKeyGenerationParameters(this.random, MLKEMParameters.ml_kem_1024);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCKyberPublicKey((MLKEMPublicKeyParameters) generateKeyPair.getPublic()), new BCKyberPrivateKey((MLKEMPrivateKeyParameters) generateKeyPair.getPrivate()));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        String nameFromParams = getNameFromParams(algorithmParameterSpec);
        if (nameFromParams == null || !parameters.containsKey(nameFromParams)) {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + algorithmParameterSpec);
        }
        MLKEMParameters mLKEMParameters = (MLKEMParameters) parameters.get(nameFromParams);
        this.param = new MLKEMKeyGenerationParameters(secureRandom, mLKEMParameters);
        if (this.kyberParameters != null && !mLKEMParameters.getName().equals(this.kyberParameters.getName())) {
            throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(this.kyberParameters.getName()));
        }
        this.engine.init(this.param);
        this.initialised = true;
    }
}