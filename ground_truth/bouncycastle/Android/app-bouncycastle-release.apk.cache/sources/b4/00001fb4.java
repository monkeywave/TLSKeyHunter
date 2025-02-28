package org.bouncycastle.jcajce.provider.asymmetric;

import org.bouncycastle.asn1.p006bc.BCObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi;

/* loaded from: classes2.dex */
public class NTRU {
    private static final String PREFIX = "org.bouncycastle.pqc.jcajce.provider.ntru.";

    /* loaded from: classes2.dex */
    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("KeyFactory.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyFactorySpi");
            configurableProvider.addAlgorithm("KeyPairGenerator.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyPairGeneratorSpi");
            configurableProvider.addAlgorithm("KeyGenerator.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUKeyGeneratorSpi");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps2048509, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps2048677, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps4096821, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhps40961229, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhrss701, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator." + BCObjectIdentifiers.ntruhrss1373, "NTRU");
            NTRUKeyFactorySpi nTRUKeyFactorySpi = new NTRUKeyFactorySpi();
            configurableProvider.addAlgorithm("Cipher.NTRU", "org.bouncycastle.pqc.jcajce.provider.ntru.NTRUCipherSpi$Base");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.pqc_kem_ntru, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps2048509, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps2048677, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps4096821, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhps40961229, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhrss701, "NTRU");
            configurableProvider.addAlgorithm("Alg.Alias.Cipher." + BCObjectIdentifiers.ntruhrss1373, "NTRU");
            registerOid(configurableProvider, BCObjectIdentifiers.pqc_kem_ntru, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhps2048509, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhps2048677, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhps4096821, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhps40961229, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhrss701, "NTRU", nTRUKeyFactorySpi);
            registerOid(configurableProvider, BCObjectIdentifiers.ntruhrss1373, "NTRU", nTRUKeyFactorySpi);
        }
    }
}