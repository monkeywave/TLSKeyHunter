package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

/* loaded from: classes2.dex */
public class SLHDSA {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.";

    /* loaded from: classes2.dex */
    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("KeyFactory.SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Pure");
            configurableProvider.addAlgorithm("KeyPairGenerator.SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Pure");
            configurableProvider.addAlgorithm("KeyFactory.HASH-SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Hash");
            configurableProvider.addAlgorithm("KeyPairGenerator.HASH-SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Hash");
            SLHDSAKeyFactorySpi.Hash hash = new SLHDSAKeyFactorySpi.Hash();
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-128S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_128s", NISTObjectIdentifiers.id_slh_dsa_sha2_128s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-128F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_128f", NISTObjectIdentifiers.id_slh_dsa_sha2_128f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-192S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_192s", NISTObjectIdentifiers.id_slh_dsa_sha2_192s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-192F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_192f", NISTObjectIdentifiers.id_slh_dsa_sha2_192f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-256S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_256s", NISTObjectIdentifiers.id_slh_dsa_sha2_256s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-256F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Sha2_256f", NISTObjectIdentifiers.id_slh_dsa_sha2_256f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_128s", NISTObjectIdentifiers.id_slh_dsa_shake_128s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_128f", NISTObjectIdentifiers.id_slh_dsa_shake_128f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_192s", NISTObjectIdentifiers.id_slh_dsa_shake_192s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_192f", NISTObjectIdentifiers.id_slh_dsa_shake_192f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_256s", NISTObjectIdentifiers.id_slh_dsa_shake_256s, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$Shake_256f", NISTObjectIdentifiers.id_slh_dsa_shake_256f, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-128S-WITH-SHA256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_128s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-128F-WITH-SHA256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_128f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-192S-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_192s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-192F-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_192f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-256S-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_256s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHA2-256F-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashSha2_256f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128S-WITH-SHAKE128", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_128s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128F-WITH-SHAKE128", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_128f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192S-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_192s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192F-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_192f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256S-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_256s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, hash);
            addKeyFactoryAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256F-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyFactorySpi$HashShake_256f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256, hash);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-128S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_128s", NISTObjectIdentifiers.id_slh_dsa_sha2_128s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-128F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_128f", NISTObjectIdentifiers.id_slh_dsa_sha2_128f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-192S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_192s", NISTObjectIdentifiers.id_slh_dsa_sha2_192s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-192F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_192f", NISTObjectIdentifiers.id_slh_dsa_sha2_192f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-256S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_256s", NISTObjectIdentifiers.id_slh_dsa_sha2_256s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-256F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Sha2_256f", NISTObjectIdentifiers.id_slh_dsa_sha2_256f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_128s", NISTObjectIdentifiers.id_slh_dsa_shake_128s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_128f", NISTObjectIdentifiers.id_slh_dsa_shake_128f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_192s", NISTObjectIdentifiers.id_slh_dsa_shake_192s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_192f", NISTObjectIdentifiers.id_slh_dsa_shake_192f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256S", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_256s", NISTObjectIdentifiers.id_slh_dsa_shake_256s);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256F", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$Shake_256f", NISTObjectIdentifiers.id_slh_dsa_shake_256f);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-128S-WITH-SHA256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_128s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-128F-WITH-SHA256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_128f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-192S-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_192s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-192F-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_192f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-256S-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_256s", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHA2-256F-WITH-SHA512", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashSha2_256f", NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128S-WITH-SHAKE128", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_128s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-128F-WITH-SHAKE128", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_128f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192S-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_192s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-192F-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_192f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256S-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_256s", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256);
            addKeyPairGeneratorAlgorithm(configurableProvider, "SLH-DSA-SHAKE-256F-WITH-SHAKE256", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SLHDSAKeyPairGeneratorSpi$HashShake_256f", NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256);
            String[] strArr = {"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256F", "SLH-DSA-SHAKE-128S", "SLH-DSA-SHAKE-128F", "SLH-DSA-SHAKE-192S", "SLH-DSA-SHAKE-192F", "SLH-DSA-SHAKE-256S", "SLH-DSA-SHAKE-256F"};
            String[] strArr2 = {"SLH-DSA-SHA2-128S-WITH-SHA256", "SLH-DSA-SHA2-128F-WITH-SHA256", "SLH-DSA-SHA2-192S-WITH-SHA512", "SLH-DSA-SHA2-192F-WITH-SHA512", "SLH-DSA-SHA2-256S-WITH-SHA512", "SLH-DSA-SHA2-256F-WITH-SHA512", "SLH-DSA-SHAKE-128S-WITH-SHAKE128", "SLH-DSA-SHAKE-128F-WITH-SHAKE128", "SLH-DSA-SHAKE-192S-WITH-SHAKE256", "SLH-DSA-SHAKE-192F-WITH-SHAKE256", "SLH-DSA-SHAKE-256S-WITH-SHAKE256", "SLH-DSA-SHAKE-256F-WITH-SHAKE256"};
            addSignatureAlgorithm(configurableProvider, "SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.SignatureSpi$Direct", (ASN1ObjectIdentifier) null);
            configurableProvider.addAlgorithm("Alg.Alias.Signature.SLHDSA", "SLH-DSA");
            addSignatureAlgorithm(configurableProvider, "HASH-SLH-DSA", "org.bouncycastle.jcajce.provider.asymmetric.slhdsa.HashSignatureSpi$Direct", (ASN1ObjectIdentifier) null);
            configurableProvider.addAlgorithm("Alg.Alias.Signature.HASHWITHSLHDSA", "HASH-SLH-DSA");
            for (int i = 0; i != 12; i++) {
                configurableProvider.addAlgorithm("Alg.Alias.Signature." + strArr[i], "SLH-DSA");
            }
            for (int i2 = 0; i2 != 12; i2++) {
                configurableProvider.addAlgorithm("Alg.Alias.Signature." + strArr2[i2], "HASH-SLH-DSA");
            }
            ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr = {NISTObjectIdentifiers.id_slh_dsa_sha2_128s, NISTObjectIdentifiers.id_slh_dsa_sha2_128f, NISTObjectIdentifiers.id_slh_dsa_sha2_192s, NISTObjectIdentifiers.id_slh_dsa_sha2_192f, NISTObjectIdentifiers.id_slh_dsa_sha2_256s, NISTObjectIdentifiers.id_slh_dsa_sha2_256f, NISTObjectIdentifiers.id_slh_dsa_shake_128s, NISTObjectIdentifiers.id_slh_dsa_shake_128f, NISTObjectIdentifiers.id_slh_dsa_shake_192s, NISTObjectIdentifiers.id_slh_dsa_shake_192f, NISTObjectIdentifiers.id_slh_dsa_shake_256s, NISTObjectIdentifiers.id_slh_dsa_shake_256f};
            for (int i3 = 0; i3 != 12; i3++) {
                configurableProvider.addAlgorithm("Alg.Alias.Signature." + aSN1ObjectIdentifierArr[i3], "SLH-DSA");
                configurableProvider.addAlgorithm("Alg.Alias.Signature.OID." + aSN1ObjectIdentifierArr[i3], "SLH-DSA");
            }
            ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr2 = {NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128s_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_128f_with_sha256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128s_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_shake_128f_with_shake128, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_192f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_192f_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256s_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_sha2_256f_with_sha512, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256s_with_shake256, NISTObjectIdentifiers.id_hash_slh_dsa_shake_256f_with_shake256};
            for (int i4 = 0; i4 != 12; i4++) {
                configurableProvider.addAlgorithm("Alg.Alias.Signature." + aSN1ObjectIdentifierArr2[i4], "HASH-SLH-DSA");
                configurableProvider.addAlgorithm("Alg.Alias.Signature.OID." + aSN1ObjectIdentifierArr2[i4], "HASH-SLH-DSA");
            }
        }
    }
}