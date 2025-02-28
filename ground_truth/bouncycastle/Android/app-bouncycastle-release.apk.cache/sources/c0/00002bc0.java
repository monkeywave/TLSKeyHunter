package org.bouncycastle.pqc.jcajce.provider.hqc;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCKeyPairGenerator;
import org.bouncycastle.pqc.crypto.hqc.HQCParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.hqc.HQCPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.HQCParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class HQCKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    HQCKeyPairGenerator engine;
    boolean initialised;
    HQCKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("hqc-128", HQCParameters.hqc128);
        parameters.put("hqc-192", HQCParameters.hqc192);
        parameters.put("hqc-256", HQCParameters.hqc256);
        parameters.put(HQCParameterSpec.hqc128.getName(), HQCParameters.hqc128);
        parameters.put(HQCParameterSpec.hqc192.getName(), HQCParameters.hqc192);
        parameters.put(HQCParameterSpec.hqc256.getName(), HQCParameters.hqc256);
    }

    public HQCKeyPairGeneratorSpi() {
        super("HQC");
        this.engine = new HQCKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof HQCParameterSpec ? ((HQCParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            HQCKeyGenerationParameters hQCKeyGenerationParameters = new HQCKeyGenerationParameters(this.random, HQCParameters.hqc128);
            this.param = hQCKeyGenerationParameters;
            this.engine.init(hQCKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCHQCPublicKey((HQCPublicKeyParameters) generateKeyPair.getPublic()), new BCHQCPrivateKey((HQCPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        HQCKeyGenerationParameters hQCKeyGenerationParameters = new HQCKeyGenerationParameters(secureRandom, (HQCParameters) parameters.get(nameFromParams));
        this.param = hQCKeyGenerationParameters;
        this.engine.init(hQCKeyGenerationParameters);
        this.initialised = true;
    }
}