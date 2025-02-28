package org.bouncycastle.jcajce.provider.digest;

import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s.class */
public class Blake2s {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s$Blake2s128.class */
    public static class Blake2s128 extends BCMessageDigest implements Cloneable {
        public Blake2s128() {
            super(new Blake2sDigest(128));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake2s128 blake2s128 = (Blake2s128) super.clone();
            blake2s128.digest = new Blake2sDigest((Blake2sDigest) this.digest);
            return blake2s128;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s$Blake2s160.class */
    public static class Blake2s160 extends BCMessageDigest implements Cloneable {
        public Blake2s160() {
            super(new Blake2sDigest((int) Opcode.IF_ICMPNE));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake2s160 blake2s160 = (Blake2s160) super.clone();
            blake2s160.digest = new Blake2sDigest((Blake2sDigest) this.digest);
            return blake2s160;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s$Blake2s224.class */
    public static class Blake2s224 extends BCMessageDigest implements Cloneable {
        public Blake2s224() {
            super(new Blake2sDigest((int) BERTags.FLAGS));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake2s224 blake2s224 = (Blake2s224) super.clone();
            blake2s224.digest = new Blake2sDigest((Blake2sDigest) this.digest);
            return blake2s224;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s$Blake2s256.class */
    public static class Blake2s256 extends BCMessageDigest implements Cloneable {
        public Blake2s256() {
            super(new Blake2sDigest(256));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake2s256 blake2s256 = (Blake2s256) super.clone();
            blake2s256.digest = new Blake2sDigest((Blake2sDigest) this.digest);
            return blake2s256;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Blake2s$Mappings.class */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Blake2s.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-256", PREFIX + "$Blake2s256");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s256, "BLAKE2S-256");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-224", PREFIX + "$Blake2s224");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s224, "BLAKE2S-224");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-160", PREFIX + "$Blake2s160");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s160, "BLAKE2S-160");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-128", PREFIX + "$Blake2s128");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s128, "BLAKE2S-128");
        }
    }

    private Blake2s() {
    }
}