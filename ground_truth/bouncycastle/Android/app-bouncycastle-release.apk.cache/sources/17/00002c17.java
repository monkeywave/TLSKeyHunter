package org.bouncycastle.pqc.jcajce.provider.picnic;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyGenerationParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicKeyPairGenerator;
import org.bouncycastle.pqc.crypto.picnic.PicnicParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPrivateKeyParameters;
import org.bouncycastle.pqc.crypto.picnic.PicnicPublicKeyParameters;
import org.bouncycastle.pqc.jcajce.provider.util.SpecUtil;
import org.bouncycastle.pqc.jcajce.spec.PicnicParameterSpec;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class PicnicKeyPairGeneratorSpi extends KeyPairGenerator {
    private static Map parameters;
    PicnicKeyPairGenerator engine;
    boolean initialised;
    PicnicKeyGenerationParameters param;
    SecureRandom random;

    static {
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put(PicnicParameterSpec.picnicl1fs.getName(), PicnicParameters.picnicl1fs);
        parameters.put(PicnicParameterSpec.picnicl1ur.getName(), PicnicParameters.picnicl1ur);
        parameters.put(PicnicParameterSpec.picnicl3fs.getName(), PicnicParameters.picnicl3fs);
        parameters.put(PicnicParameterSpec.picnicl3ur.getName(), PicnicParameters.picnicl3ur);
        parameters.put(PicnicParameterSpec.picnicl5fs.getName(), PicnicParameters.picnicl5fs);
        parameters.put(PicnicParameterSpec.picnicl5ur.getName(), PicnicParameters.picnicl5ur);
        parameters.put(PicnicParameterSpec.picnic3l1.getName(), PicnicParameters.picnic3l1);
        parameters.put(PicnicParameterSpec.picnic3l3.getName(), PicnicParameters.picnic3l3);
        parameters.put(PicnicParameterSpec.picnic3l5.getName(), PicnicParameters.picnic3l5);
        parameters.put(PicnicParameterSpec.picnicl1full.getName(), PicnicParameters.picnicl1full);
        parameters.put(PicnicParameterSpec.picnicl3full.getName(), PicnicParameters.picnicl3full);
        parameters.put(PicnicParameterSpec.picnicl5full.getName(), PicnicParameters.picnicl5full);
    }

    public PicnicKeyPairGeneratorSpi() {
        super("Picnic");
        this.engine = new PicnicKeyPairGenerator();
        this.random = CryptoServicesRegistrar.getSecureRandom();
        this.initialised = false;
    }

    private static String getNameFromParams(AlgorithmParameterSpec algorithmParameterSpec) {
        return algorithmParameterSpec instanceof PicnicParameterSpec ? ((PicnicParameterSpec) algorithmParameterSpec).getName() : Strings.toLowerCase(SpecUtil.getNameFrom(algorithmParameterSpec));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        if (!this.initialised) {
            PicnicKeyGenerationParameters picnicKeyGenerationParameters = new PicnicKeyGenerationParameters(this.random, PicnicParameters.picnicl3ur);
            this.param = picnicKeyGenerationParameters;
            this.engine.init(picnicKeyGenerationParameters);
            this.initialised = true;
        }
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCPicnicPublicKey((PicnicPublicKeyParameters) generateKeyPair.getPublic()), new BCPicnicPrivateKey((PicnicPrivateKeyParameters) generateKeyPair.getPrivate()));
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
        PicnicKeyGenerationParameters picnicKeyGenerationParameters = new PicnicKeyGenerationParameters(secureRandom, (PicnicParameters) parameters.get(nameFromParams));
        this.param = picnicKeyGenerationParameters;
        this.engine.init(picnicKeyGenerationParameters);
        this.initialised = true;
    }
}