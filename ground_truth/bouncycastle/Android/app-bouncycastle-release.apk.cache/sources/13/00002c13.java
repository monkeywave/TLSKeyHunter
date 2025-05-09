package org.bouncycastle.pqc.jcajce.provider.ntruprime;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.SNTRUPrimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SNTRUPrimeParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SNTRUPrimeKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    SNTRUPrimeKeyPairGenerator engine;
    boolean initialised;
    SNTRUPrimeKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(SNTRUPrimeParameterSpec.sntrup653.getName(), SNTRUPrimeParameters.sntrup653);
        parameters.put(SNTRUPrimeParameterSpec.sntrup761.getName(), SNTRUPrimeParameters.sntrup761);
        parameters.put(SNTRUPrimeParameterSpec.sntrup857.getName(), SNTRUPrimeParameters.sntrup857);
        parameters.put(SNTRUPrimeParameterSpec.sntrup953.getName(), SNTRUPrimeParameters.sntrup953);
        parameters.put(SNTRUPrimeParameterSpec.sntrup1013.getName(), SNTRUPrimeParameters.sntrup1013);
        parameters.put(SNTRUPrimeParameterSpec.sntrup1277.getName(), SNTRUPrimeParameters.sntrup1277);
    }

    public SNTRUPrimeKeyPairGeneratorSpi() {
        super("SNTRUPrime");
        this.engine = new SNTRUPrimeKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof SNTRUPrimeParameterSpec ? ((SNTRUPrimeParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            SNTRUPrimeKeyGenerationParameters sNTRUPrimeKeyGenerationParameters = new SNTRUPrimeKeyGenerationParameters(this.random, SNTRUPrimeParameters.sntrup953);
            this.param = sNTRUPrimeKeyGenerationParameters;
            this.engine.init(sNTRUPrimeKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCSNTRUPrimePublicKey((SNTRUPrimePublicKeyParameters) generateKeyPair.getPublic()), new BCSNTRUPrimePrivateKey((SNTRUPrimePrivateKeyParameters) generateKeyPair.getPrivate()));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        throw new IllegalArgumentException("use AlgorithmParameterSpec");
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        String nameFromParams = getNameFromParams(algorithmParameterSpec);
        if (nameFromParams == null) {
            throw new InvalidAlgorithmParameterException("invalid ParameterSpec: " + algorithmParameterSpec);
        }
        SNTRUPrimeKeyGenerationParameters sNTRUPrimeKeyGenerationParameters = new SNTRUPrimeKeyGenerationParameters(secureRandom, (SNTRUPrimeParameters) parameters.get(nameFromParams));
        this.param = sNTRUPrimeKeyGenerationParameters;
        this.engine.init(sNTRUPrimeKeyGenerationParameters);
        this.initialised = true;
    }
}