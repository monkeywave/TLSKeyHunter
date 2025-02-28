package org.bouncycastle.pqc.jcajce.provider.saber;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.saber.SABERKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.saber.SABERKeyPairGenerator;
import org.bouncycastle.pqc.crypto.saber.SABERParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.saber.SABERPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SABERParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SABERKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    SABERKeyPairGenerator engine;
    boolean initialised;
    SABERKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(SABERParameterSpec.lightsaberkem128r3.getName(), SABERParameters.lightsaberkem128r3);
        parameters.put(SABERParameterSpec.saberkem128r3.getName(), SABERParameters.saberkem128r3);
        parameters.put(SABERParameterSpec.firesaberkem128r3.getName(), SABERParameters.firesaberkem128r3);
        parameters.put(SABERParameterSpec.lightsaberkem192r3.getName(), SABERParameters.lightsaberkem192r3);
        parameters.put(SABERParameterSpec.saberkem192r3.getName(), SABERParameters.saberkem192r3);
        parameters.put(SABERParameterSpec.firesaberkem192r3.getName(), SABERParameters.firesaberkem192r3);
        parameters.put(SABERParameterSpec.lightsaberkem256r3.getName(), SABERParameters.lightsaberkem256r3);
        parameters.put(SABERParameterSpec.saberkem256r3.getName(), SABERParameters.saberkem256r3);
        parameters.put(SABERParameterSpec.firesaberkem256r3.getName(), SABERParameters.firesaberkem256r3);
    }

    public SABERKeyPairGeneratorSpi() {
        super("SABER");
        this.engine = new SABERKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof SABERParameterSpec ? ((SABERParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            SABERKeyGenerationParameters sABERKeyGenerationParameters = new SABERKeyGenerationParameters(this.random, SABERParameters.firesaberkem256r3);
            this.param = sABERKeyGenerationParameters;
            this.engine.init(sABERKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCSABERPublicKey((SABERPublicKeyParameters) generateKeyPair.getPublic()), new BCSABERPrivateKey((SABERPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        SABERKeyGenerationParameters sABERKeyGenerationParameters = new SABERKeyGenerationParameters(secureRandom, (SABERParameters) parameters.get(nameFromParams));
        this.param = sABERKeyGenerationParameters;
        this.engine.init(sABERKeyGenerationParameters);
        this.initialised = true;
    }
}