package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.crypto.digests.Blake3Digest;
import org.bouncycastle.internal.asn1.misc.MiscObjectIdentifiers;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

/* loaded from: classes2.dex */
public class Blake3 {

    /* loaded from: classes2.dex */
    public static class Blake3_256 extends BCMessageDigest implements Cloneable {
        public Blake3_256() {
            super(new Blake3Digest(256));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Blake3_256 blake3_256 = (Blake3_256) super.clone();
            blake3_256.digest = new Blake3Digest((Blake3Digest) this.digest);
            return blake3_256;
        }
    }

    /* loaded from: classes2.dex */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Blake3.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("MessageDigest.BLAKE3-256", PREFIX + "$Blake3_256");
            configurableProvider.addAlgorithm("Alg.Alias.MessageDigest." + MiscObjectIdentifiers.blake3_256, "BLAKE3-256");
        }
    }

    private Blake3() {
    }
}