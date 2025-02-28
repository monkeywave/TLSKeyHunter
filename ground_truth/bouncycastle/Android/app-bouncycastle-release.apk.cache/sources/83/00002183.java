package org.bouncycastle.jcajce.provider.asymmetric.rsa;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.jcajce.provider.asymmetric.util.PrimeCertaintyCalculator;

/* loaded from: classes2.dex */
public class KeyPairGeneratorSpi extends KeyPairGenerator {
    private static final AlgorithmIdentifier PKCS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE);
    private static final AlgorithmIdentifier PSS_ALGID = new AlgorithmIdentifier(PKCSObjectIdentifiers.id_RSASSA_PSS);
    static final BigInteger defaultPublicExponent = BigInteger.valueOf(65537);
    AlgorithmIdentifier algId;
    RSAKeyPairGenerator engine;
    RSAKeyGenerationParameters param;

    /* loaded from: classes2.dex */
    public static class PSS extends KeyPairGeneratorSpi {
        public PSS() {
            super("RSASSA-PSS", KeyPairGeneratorSpi.PSS_ALGID);
        }
    }

    public KeyPairGeneratorSpi() {
        this("RSA", PKCS_ALGID);
    }

    public KeyPairGeneratorSpi(String str, AlgorithmIdentifier algorithmIdentifier) {
        super(str);
        this.algId = algorithmIdentifier;
        this.engine = new RSAKeyPairGenerator();
        RSAKeyGenerationParameters rSAKeyGenerationParameters = new RSAKeyGenerationParameters(defaultPublicExponent, CryptoServicesRegistrar.getSecureRandom(), 2048, PrimeCertaintyCalculator.getDefaultCertainty(2048));
        this.param = rSAKeyGenerationParameters;
        this.engine.init(rSAKeyGenerationParameters);
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public KeyPair generateKeyPair() {
        AsymmetricCipherKeyPair generateKeyPair = this.engine.generateKeyPair();
        return new KeyPair(new BCRSAPublicKey(this.algId, (RSAKeyParameters) generateKeyPair.getPublic()), new BCRSAPrivateCrtKey(this.algId, (RSAPrivateCrtKeyParameters) generateKeyPair.getPrivate()));
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(int i, SecureRandom secureRandom) {
        RSAKeyGenerationParameters rSAKeyGenerationParameters = new RSAKeyGenerationParameters(defaultPublicExponent, secureRandom, i, PrimeCertaintyCalculator.getDefaultCertainty(i));
        this.param = rSAKeyGenerationParameters;
        this.engine.init(rSAKeyGenerationParameters);
    }

    @Override // java.security.KeyPairGenerator, java.security.KeyPairGeneratorSpi
    public void initialize(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        if (!(algorithmParameterSpec instanceof RSAKeyGenParameterSpec)) {
            throw new InvalidAlgorithmParameterException("parameter object not a RSAKeyGenParameterSpec");
        }
        RSAKeyGenParameterSpec rSAKeyGenParameterSpec = (RSAKeyGenParameterSpec) algorithmParameterSpec;
        RSAKeyGenerationParameters rSAKeyGenerationParameters = new RSAKeyGenerationParameters(rSAKeyGenParameterSpec.getPublicExponent(), secureRandom, rSAKeyGenParameterSpec.getKeysize(), PrimeCertaintyCalculator.getDefaultCertainty(2048));
        this.param = rSAKeyGenerationParameters;
        this.engine.init(rSAKeyGenerationParameters);
    }
}