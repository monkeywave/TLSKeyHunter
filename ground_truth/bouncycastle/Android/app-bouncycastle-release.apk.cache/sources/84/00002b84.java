package org.bouncycastle.pqc.jcajce.provider.bike;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.bike.BIKEParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.bike.BIKEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.BIKEParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class BIKEKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    BIKEKeyPairGenerator engine;
    boolean initialised;
    BIKEKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("bike128", BIKEParameters.bike128);
        parameters.put("bike192", BIKEParameters.bike192);
        parameters.put("bike256", BIKEParameters.bike256);
        parameters.put(BIKEParameterSpec.bike128.getName(), BIKEParameters.bike128);
        parameters.put(BIKEParameterSpec.bike192.getName(), BIKEParameters.bike192);
        parameters.put(BIKEParameterSpec.bike256.getName(), BIKEParameters.bike256);
    }

    public BIKEKeyPairGeneratorSpi() {
        super("BIKE");
        this.engine = new BIKEKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof BIKEParameterSpec ? ((BIKEParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            BIKEKeyGenerationParameters bIKEKeyGenerationParameters = new BIKEKeyGenerationParameters(this.random, BIKEParameters.bike128);
            this.param = bIKEKeyGenerationParameters;
            this.engine.init(bIKEKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCBIKEPublicKey((BIKEPublicKeyParameters) generateKeyPair.getPublic()), new BCBIKEPrivateKey((BIKEPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        BIKEKeyGenerationParameters bIKEKeyGenerationParameters = new BIKEKeyGenerationParameters(secureRandom, (BIKEParameters) parameters.get(nameFromParams));
        this.param = bIKEKeyGenerationParameters;
        this.engine.init(bIKEKeyGenerationParameters);
        this.initialised = true;
    }
}