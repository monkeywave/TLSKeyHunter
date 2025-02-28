package org.bouncycastle.pqc.jcajce.provider.rainbow;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowKeyPairGenerator;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.rainbow.RainbowPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.RainbowParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class RainbowKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    RainbowKeyPairGenerator engine;
    boolean initialised;
    RainbowKeyGenerationParameters param;
    private final RainbowParameters rainbowParameters;
    SecureRandom random;

    /* loaded from: classes2.dex */
    public static class RainbowIIIcircum extends RainbowKeyPairGeneratorSpi {
        public RainbowIIIcircum() {
            super(RainbowParameters.rainbowIIIcircumzenithal);
        }
    }

    /* loaded from: classes2.dex */
    public static class RainbowIIIclassic extends RainbowKeyPairGeneratorSpi {
        public RainbowIIIclassic() {
            super(RainbowParameters.rainbowIIIclassic);
        }
    }

    /* loaded from: classes2.dex */
    public static class RainbowIIIcomp extends RainbowKeyPairGeneratorSpi {
        public RainbowIIIcomp() {
            super(RainbowParameters.rainbowIIIcompressed);
        }
    }

    /* loaded from: classes2.dex */
    public static class RainbowVcircum extends RainbowKeyPairGeneratorSpi {
        public RainbowVcircum() {
            super(RainbowParameters.rainbowVcircumzenithal);
        }
    }

    /* loaded from: classes2.dex */
    public static class RainbowVclassic extends RainbowKeyPairGeneratorSpi {
        public RainbowVclassic() {
            super(RainbowParameters.rainbowVclassic);
        }
    }

    /* loaded from: classes2.dex */
    public static class RainbowVcomp extends RainbowKeyPairGeneratorSpi {
        public RainbowVcomp() {
            super(RainbowParameters.rainbowVcompressed);
        }
    }

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(RainbowParameterSpec.rainbowIIIclassic.getName(), RainbowParameters.rainbowIIIclassic);
        parameters.put(RainbowParameterSpec.rainbowIIIcircumzenithal.getName(), RainbowParameters.rainbowIIIcircumzenithal);
        parameters.put(RainbowParameterSpec.rainbowIIIcompressed.getName(), RainbowParameters.rainbowIIIcompressed);
        parameters.put(RainbowParameterSpec.rainbowVclassic.getName(), RainbowParameters.rainbowVclassic);
        parameters.put(RainbowParameterSpec.rainbowVcircumzenithal.getName(), RainbowParameters.rainbowVcircumzenithal);
        parameters.put(RainbowParameterSpec.rainbowVcompressed.getName(), RainbowParameters.rainbowVcompressed);
    }

    public RainbowKeyPairGeneratorSpi() {
        super("RAINBOW");
        this.engine = new RainbowKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.rainbowParameters = null;
    }

    protected RainbowKeyPairGeneratorSpi(RainbowParameters rainbowParameters) {
        super(rainbowParameters.getName());
        this.engine = new RainbowKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
        this.rainbowParameters = rainbowParameters;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof RainbowParameterSpec ? ((RainbowParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            this.param = this.rainbowParameters != null ? new RainbowKeyGenerationParameters(this.random, this.rainbowParameters) : new RainbowKeyGenerationParameters(this.random, RainbowParameters.rainbowIIIclassic);
            this.engine.init(this.param);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCRainbowPublicKey((RainbowPublicKeyParameters) generateKeyPair.getPublic()), new BCRainbowPrivateKey((RainbowPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        RainbowParameters rainbowParameters = (RainbowParameters) parameters.get(nameFromParams);
        this.param = new RainbowKeyGenerationParameters(secureRandom, rainbowParameters);
        if (this.rainbowParameters != null && !rainbowParameters.getName().equals(this.rainbowParameters.getName())) {
            throw new InvalidAlgorithmParameterException("key pair generator locked to " + Strings.toUpperCase(this.rainbowParameters.getName()));
        }
        this.engine.init(this.param);
        this.initialised = true;
    }
}