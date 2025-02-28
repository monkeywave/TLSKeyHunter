package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.digests.Blake2sDigest;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.tls.CipherSuite;

/* loaded from: classes2.dex */
public class Blake2s {

    /* loaded from: classes2.dex */
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

    /* loaded from: classes2.dex */
    public static class Blake2s160 extends BCMessageDigest implements Cloneable {
        public Blake2s160() {
            super(new Blake2sDigest((int) CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake2s160 blake2s160 = (Blake2s160) super.clone();
            blake2s160.digest = new Blake2sDigest((Blake2sDigest) this.digest);
            return blake2s160;
        }
    }

    /* loaded from: classes2.dex */
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

    /* loaded from: classes2.dex */
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

    /* loaded from: classes2.dex */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Blake2s.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            StringBuilder sb = new StringBuilder();
            String str = PREFIX;
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-256", sb.append(str).append("$Blake2s256").toString());
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s256, "BLAKE2S-256");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-224", str + "$Blake2s224");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s224, "BLAKE2S-224");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-160", str + "$Blake2s160");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s160, "BLAKE2S-160");
            configurableProvider.addAlgorithm("MessageDigest.BLAKE2S-128", str + "$Blake2s128");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.id_blake2s128, "BLAKE2S-128");
        }
    }

    private Blake2s() {
    }
}