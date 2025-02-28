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
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeKeyPairGenerator;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimeParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePrivateKeyParameters;
import org.bouncycastle.pqc.crypto.ntruprime.NTRULPRimePublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.NTRULPRimeParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class NTRULPRimeKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    NTRULPRimeKeyPairGenerator engine;
    boolean initialised;
    NTRULPRimeKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(NTRULPRimeParameterSpec.ntrulpr653.getName(), NTRULPRimeParameters.ntrulpr653);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr761.getName(), NTRULPRimeParameters.ntrulpr761);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr857.getName(), NTRULPRimeParameters.ntrulpr857);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr953.getName(), NTRULPRimeParameters.ntrulpr953);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr1013.getName(), NTRULPRimeParameters.ntrulpr1013);
        parameters.put(NTRULPRimeParameterSpec.ntrulpr1277.getName(), NTRULPRimeParameters.ntrulpr1277);
    }

    public NTRULPRimeKeyPairGeneratorSpi() {
        super("NTRULPRime");
        this.engine = new NTRULPRimeKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof NTRULPRimeParameterSpec ? ((NTRULPRimeParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            NTRULPRimeKeyGenerationParameters nTRULPRimeKeyGenerationParameters = new NTRULPRimeKeyGenerationParameters(this.random, NTRULPRimeParameters.ntrulpr953);
            this.param = nTRULPRimeKeyGenerationParameters;
            this.engine.init(nTRULPRimeKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCNTRULPRimePublicKey((NTRULPRimePublicKeyParameters) generateKeyPair.getPublic()), new BCNTRULPRimePrivateKey((NTRULPRimePrivateKeyParameters) generateKeyPair.getPrivate()));
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
        NTRULPRimeKeyGenerationParameters nTRULPRimeKeyGenerationParameters = new NTRULPRimeKeyGenerationParameters(secureRandom, (NTRULPRimeParameters) parameters.get(nameFromParams));
        this.param = nTRULPRimeKeyGenerationParameters;
        this.engine.init(nTRULPRimeKeyGenerationParameters);
        this.initialised = true;
    }
}