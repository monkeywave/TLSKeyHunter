package org.bouncycastle.jcajce.provider.asymmetric.mlkem;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLKEMParameterSpec;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class MLKEMKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    MLKEMKeyPairGenerator engine;
    boolean initialised;
    private MLKEMParameters kyberParameters;
    MLKEMKeyGenerationParameters param;
    SecureRandom random;

    /* loaded from: classes2.dex */
    public static class MLKEM1024 extends MLKEMKeyPairGeneratorSpi {
        public MLKEM1024() {
            super(MLKEMParameterSpec.ml_kem_1024);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM512 extends MLKEMKeyPairGeneratorSpi {
        public MLKEM512() {
            super(MLKEMParameterSpec.ml_kem_512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLKEM768 extends MLKEMKeyPairGeneratorSpi {
        public MLKEM768() {
            super(MLKEMParameterSpec.ml_kem_768);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(MLKEMParameterSpec.ml_kem_512.getName(), MLKEMParameters.ml_kem_512);
        parameters.put(MLKEMParameterSpec.ml_kem_768.getName(), MLKEMParameters.ml_kem_768);
        parameters.put(MLKEMParameterSpec.ml_kem_1024.getName(), MLKEMParameters.ml_kem_1024);
    }

    public MLKEMKeyPairGeneratorSpi() {
        super("ML-KEM");
        this.engine = new MLKEMKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    protected MLKEMKeyPairGeneratorSpi(MLKEMParameterSpec mLKEMParameterSpec) {
        super(Strings.toUpperCase(mLKEMParameterSpec.getName()));
        this.engine = new MLKEMKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.kyberParameters = (MLKEMParameters) parameters.get(mLKEMParameterSpec.getName());
        if (this.param == null) {
            this.param = new MLKEMKeyGenerationParameters(this.random, this.kyberParameters);
        }
        this.engine.init(this.param);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof MLKEMParameterSpec ? ((MLKEMParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            MLKEMKeyGenerationParameters mLKEMKeyGenerationParameters = new MLKEMKeyGenerationParameters(this.random, MLKEMParameters.ml_kem_768);
            this.param = mLKEMKeyGenerationParameters;
            this.engine.init(mLKEMKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCMLKEMPublicKey((MLKEMPublicKeyParameters) generateKeyPair.getPublic()), new BCMLKEMPrivateKey((MLKEMPrivateKeyParameters) generateKeyPair.getPrivate()));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        String nameFromParams = getNameFromParams(algorithmParameterSpec);
        MLKEMParameters mLKEMParameters = (MLKEMParameters) parameters.get(nameFromParams);
        if (nameFromParams == null) {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + algorithmParameterSpec);
        }
        this.param = new MLKEMKeyGenerationParameters(secureRandom, (MLKEMParameters) parameters.get(nameFromParams));
        if (this.kyberParameters != null && !mLKEMParameters.getName().equals(this.kyberParameters.getName())) {
            throw new InvalidAlgorithmParameterException("key pair generator locked to " + getAlgorithm());
        }
        this.engine.init(this.param);
        this.initialised = true;
    }
}