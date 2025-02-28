package org.bouncycastle.jcajce.provider.asymmetric.mldsa;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.jcajce.spec.MLDSAParameterSpec;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAKeyPairGenerator;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mldsa.MLDSAPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class MLDSAKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    MLDSAKeyPairGenerator engine;
    boolean initialised;
    private final MLDSAParameters mldsaParameters;
    MLDSAKeyGenerationParameters param;
    SecureRandom random;

    /* loaded from: classes2.dex */
    public static class Hash extends MLDSAKeyPairGeneratorSpi {
        public Hash() throws NoSuchAlgorithmException {
            super("HASH-ML-DSA");
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA44 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA44() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_44);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA44withSHA512 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA44withSHA512() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_44_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA65 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA65() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_65);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA65withSHA512 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA65withSHA512() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_65_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA87 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA87() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_87);
        }
    }

    /* loaded from: classes2.dex */
    public static class MLDSA87withSHA512 extends MLDSAKeyPairGeneratorSpi {
        public MLDSA87withSHA512() throws NoSuchAlgorithmException {
            super(MLDSAParameterSpec.ml_dsa_87_with_sha512);
        }
    }

    /* loaded from: classes2.dex */
    public static class Pure extends MLDSAKeyPairGeneratorSpi {
        public Pure() throws NoSuchAlgorithmException {
            super("ML-DSA");
        }
    }

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(MLDSAParameterSpec.ml_dsa_44.getName(), MLDSAParameters.ml_dsa_44);
        parameters.put(MLDSAParameterSpec.ml_dsa_65.getName(), MLDSAParameters.ml_dsa_65);
        parameters.put(MLDSAParameterSpec.ml_dsa_87.getName(), MLDSAParameters.ml_dsa_87);
        parameters.put(MLDSAParameterSpec.ml_dsa_44_with_sha512.getName(), MLDSAParameters.ml_dsa_44_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_65_with_sha512.getName(), MLDSAParameters.ml_dsa_65_with_sha512);
        parameters.put(MLDSAParameterSpec.ml_dsa_87_with_sha512.getName(), MLDSAParameters.ml_dsa_87_with_sha512);
    }

    public MLDSAKeyPairGeneratorSpi(String str) {
        super(str);
        this.engine = new MLDSAKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.mldsaParameters = null;
    }

    protected MLDSAKeyPairGeneratorSpi(MLDSAParameterSpec mLDSAParameterSpec) {
        super(Strings.toUpperCase(mLDSAParameterSpec.getName()));
        this.engine = new MLDSAKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        MLDSAParameters mLDSAParameters = (MLDSAParameters) parameters.get(mLDSAParameterSpec.getName());
        this.mldsaParameters = mLDSAParameters;
        if (this.param == null) {
            this.param = new MLDSAKeyGenerationParameters(this.random, mLDSAParameters);
        }
        this.engine.init(this.param);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof MLDSAParameterSpec ? ((MLDSAParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = getAlgorithm().startsWith("HASH") ? new MLDSAKeyGenerationParameters(this.random, MLDSAParameters.ml_dsa_87_with_sha512) : new MLDSAKeyGenerationParameters(this.random, MLDSAParameters.ml_dsa_87);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCMLDSAPublicKey((MLDSAPublicKeyParameters) generateKeyPair.getPublic()), new BCMLDSAPrivateKey((MLDSAPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        MLDSAParameters mLDSAParameters = (MLDSAParameters) parameters.get(nameFromParams);
        this.param = new MLDSAKeyGenerationParameters(secureRandom, (MLDSAParameters) parameters.get(nameFromParams));
        if (this.mldsaParameters != null && !mLDSAParameters.getName().equals(this.mldsaParameters.getName())) {
            throw new InvalidAlgorithmParameterException("key pair generator locked to " + MLDSAParameterSpec.fromName(this.mldsaParameters.getName()).getName());
        }
        this.engine.init(this.param);
        this.initialised = true;
    }
}