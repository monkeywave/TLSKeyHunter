package org.bouncycastle.pqc.jcajce.provider.sphincsplus;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusKeyPairGenerator;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.sphincsplus.SPHINCSPlusPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SPHINCSPlusKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    SPHINCSPlusKeyPairGenerator engine;
    boolean initialised;
    SPHINCSPlusKeyGenerationParameters param;
    SecureRandom random;

    /* loaded from: classes2.dex */
    public static class Sha2_128f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_128f() {
            super(SPHINCSPlusParameterSpec.sha2_128f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_128s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_128s() {
            super(SPHINCSPlusParameterSpec.sha2_128s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_192f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_192f() {
            super(SPHINCSPlusParameterSpec.sha2_192f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_192s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_192s() {
            super(SPHINCSPlusParameterSpec.sha2_192s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_256f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_256f() {
            super(SPHINCSPlusParameterSpec.sha2_256f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Sha2_256s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Sha2_256s() {
            super(SPHINCSPlusParameterSpec.sha2_256s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_128f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_128f() {
            super(SPHINCSPlusParameterSpec.shake_128f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_128s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_128s() {
            super(SPHINCSPlusParameterSpec.shake_128s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_192f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_192f() {
            super(SPHINCSPlusParameterSpec.shake_192f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_192s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_192s() {
            super(SPHINCSPlusParameterSpec.shake_192s);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_256f extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_256f() {
            super(SPHINCSPlusParameterSpec.shake_256f);
        }
    }

    /* loaded from: classes2.dex */
    public static class Shake_256s extends SPHINCSPlusKeyPairGeneratorSpi {
        public Shake_256s() {
            super(SPHINCSPlusParameterSpec.shake_256s);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(SPHINCSPlusParameterSpec.sha2_128f_robust.getName(), SPHINCSPlusParameters.sha2_128f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s_robust.getName(), SPHINCSPlusParameters.sha2_128s_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f_robust.getName(), SPHINCSPlusParameters.sha2_192f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s_robust.getName(), SPHINCSPlusParameters.sha2_192s_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f_robust.getName(), SPHINCSPlusParameters.sha2_256f_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s_robust.getName(), SPHINCSPlusParameters.sha2_256s_robust);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128f.getName(), SPHINCSPlusParameters.sha2_128f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_128s.getName(), SPHINCSPlusParameters.sha2_128s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192f.getName(), SPHINCSPlusParameters.sha2_192f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_192s.getName(), SPHINCSPlusParameters.sha2_192s);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256f.getName(), SPHINCSPlusParameters.sha2_256f);
        parameters.put(SPHINCSPlusParameterSpec.sha2_256s.getName(), SPHINCSPlusParameters.sha2_256s);
        parameters.put(SPHINCSPlusParameterSpec.shake_128f_robust.getName(), SPHINCSPlusParameters.shake_128f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s_robust.getName(), SPHINCSPlusParameters.shake_128s_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f_robust.getName(), SPHINCSPlusParameters.shake_192f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s_robust.getName(), SPHINCSPlusParameters.shake_192s_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f_robust.getName(), SPHINCSPlusParameters.shake_256f_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s_robust.getName(), SPHINCSPlusParameters.shake_256s_robust);
        parameters.put(SPHINCSPlusParameterSpec.shake_128f.getName(), SPHINCSPlusParameters.shake_128f);
        parameters.put(SPHINCSPlusParameterSpec.shake_128s.getName(), SPHINCSPlusParameters.shake_128s);
        parameters.put(SPHINCSPlusParameterSpec.shake_192f.getName(), SPHINCSPlusParameters.shake_192f);
        parameters.put(SPHINCSPlusParameterSpec.shake_192s.getName(), SPHINCSPlusParameters.shake_192s);
        parameters.put(SPHINCSPlusParameterSpec.shake_256f.getName(), SPHINCSPlusParameters.shake_256f);
        parameters.put(SPHINCSPlusParameterSpec.shake_256s.getName(), SPHINCSPlusParameters.shake_256s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128f.getName(), SPHINCSPlusParameters.haraka_128f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128s.getName(), SPHINCSPlusParameters.haraka_128s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192f.getName(), SPHINCSPlusParameters.haraka_192f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192s.getName(), SPHINCSPlusParameters.haraka_192s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256f.getName(), SPHINCSPlusParameters.haraka_256f);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256s.getName(), SPHINCSPlusParameters.haraka_256s);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128f_simple.getName(), SPHINCSPlusParameters.haraka_128f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_128s_simple.getName(), SPHINCSPlusParameters.haraka_128s_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192f_simple.getName(), SPHINCSPlusParameters.haraka_192f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_192s_simple.getName(), SPHINCSPlusParameters.haraka_192s_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256f_simple.getName(), SPHINCSPlusParameters.haraka_256f_simple);
        parameters.put(SPHINCSPlusParameterSpec.haraka_256s_simple.getName(), SPHINCSPlusParameters.haraka_256s_simple);
    }

    public SPHINCSPlusKeyPairGeneratorSpi() {
        super("SPHINCS+");
        this.engine = new SPHINCSPlusKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    protected SPHINCSPlusKeyPairGeneratorSpi(SPHINCSPlusParameterSpec sPHINCSPlusParameterSpec) {
        super("SPHINCS+-" + Strings.toUpperCase(sPHINCSPlusParameterSpec.getName()));
        this.engine = new SPHINCSPlusKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        SPHINCSPlusKeyGenerationParameters sPHINCSPlusKeyGenerationParameters = new SPHINCSPlusKeyGenerationParameters(this.random, (SPHINCSPlusParameters) parameters.get(sPHINCSPlusParameterSpec.getName()));
        this.param = sPHINCSPlusKeyGenerationParameters;
        this.engine.init(sPHINCSPlusKeyGenerationParameters);
        this.initialised = true;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof SPHINCSPlusParameterSpec ? ((SPHINCSPlusParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            SPHINCSPlusKeyGenerationParameters sPHINCSPlusKeyGenerationParameters = new SPHINCSPlusKeyGenerationParameters(this.random, SPHINCSPlusParameters.sha2_256s);
            this.param = sPHINCSPlusKeyGenerationParameters;
            this.engine.init(sPHINCSPlusKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCSPHINCSPlusPublicKey((SPHINCSPlusPublicKeyParameters) generateKeyPair.getPublic()), new BCSPHINCSPlusPrivateKey((SPHINCSPlusPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        SPHINCSPlusKeyGenerationParameters sPHINCSPlusKeyGenerationParameters = new SPHINCSPlusKeyGenerationParameters(secureRandom, (SPHINCSPlusParameters) parameters.get(nameFromParams));
        this.param = sPHINCSPlusKeyGenerationParameters;
        this.engine.init(sPHINCSPlusKeyGenerationParameters);
        this.initialised = true;
    }
}