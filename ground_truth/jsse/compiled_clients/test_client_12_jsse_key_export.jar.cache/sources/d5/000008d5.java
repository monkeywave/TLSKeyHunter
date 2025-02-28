package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.p001gm.GMObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.digests.SM3Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/SM3.class */
public class SM3 {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/SM3$Digest.class */
    public static class Digest extends BCMessageDigest implements Cloneable {
        public Digest() {
            super(new SM3Digest());
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Digest digest = (Digest) super.clone();
            digest.digest = new SM3Digest((SM3Digest) this.digest);
            return digest;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/SM3$HashMac.class */
    public static class HashMac extends BaseMac {
        public HashMac() {
            super(new HMac(new SM3Digest()));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/SM3$KeyGenerator.class */
    public static class KeyGenerator extends BaseKeyGenerator {
        public KeyGenerator() {
            super("HMACSM3", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/SM3$Mappings.class */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = SM3.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("MessageDigest.SM3", PREFIX + "$Digest");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest.SM3", "SM3");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest.1.2.156.197.1.401", "SM3");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + GMObjectIdentifiers.sm3, "SM3");
            addHMACAlgorithm(configurableProvider, "SM3", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
            addHMACAlias(configurableProvider, "SM3", GMObjectIdentifiers.hmac_sm3);
        }
    }

    private SM3() {
    }
}