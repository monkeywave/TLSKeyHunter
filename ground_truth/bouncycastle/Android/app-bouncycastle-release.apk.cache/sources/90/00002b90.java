package org.bouncycastle.pqc.jcajce.provider.cmce;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEKeyPairGenerator;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.cmce.CMCEPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.CMCEParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class CMCEKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    CMCEKeyPairGenerator engine;
    boolean initialised;
    CMCEKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(CMCEParameterSpec.mceliece348864.getName(), CMCEParameters.mceliece348864r3);
        parameters.put(CMCEParameterSpec.mceliece348864f.getName(), CMCEParameters.mceliece348864fr3);
        parameters.put(CMCEParameterSpec.mceliece460896.getName(), CMCEParameters.mceliece460896r3);
        parameters.put(CMCEParameterSpec.mceliece460896f.getName(), CMCEParameters.mceliece460896fr3);
        parameters.put(CMCEParameterSpec.mceliece6688128.getName(), CMCEParameters.mceliece6688128r3);
        parameters.put(CMCEParameterSpec.mceliece6688128f.getName(), CMCEParameters.mceliece6688128fr3);
        parameters.put(CMCEParameterSpec.mceliece6960119.getName(), CMCEParameters.mceliece6960119r3);
        parameters.put(CMCEParameterSpec.mceliece6960119f.getName(), CMCEParameters.mceliece6960119fr3);
        parameters.put(CMCEParameterSpec.mceliece8192128.getName(), CMCEParameters.mceliece8192128r3);
        parameters.put(CMCEParameterSpec.mceliece8192128f.getName(), CMCEParameters.mceliece8192128fr3);
    }

    public CMCEKeyPairGeneratorSpi() {
        super("CMCE");
        this.engine = new CMCEKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof CMCEParameterSpec ? ((CMCEParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            CMCEKeyGenerationParameters cMCEKeyGenerationParameters = new CMCEKeyGenerationParameters(this.random, CMCEParameters.mceliece8192128fr3);
            this.param = cMCEKeyGenerationParameters;
            this.engine.init(cMCEKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCCMCEPublicKey((CMCEPublicKeyParameters) generateKeyPair.getPublic()), new BCCMCEPrivateKey((CMCEPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        CMCEKeyGenerationParameters cMCEKeyGenerationParameters = new CMCEKeyGenerationParameters(secureRandom, (CMCEParameters) parameters.get(nameFromParams));
        this.param = cMCEKeyGenerationParameters;
        this.engine.init(cMCEKeyGenerationParameters);
        this.initialised = true;
    }
}