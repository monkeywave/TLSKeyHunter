package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.crypto.digests.Haraka256Digest;
import org.bouncycastle.crypto.digests.Haraka512Digest;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;

/* loaded from: classes2.dex */
public class Haraka {

    /* loaded from: classes2.dex */
    public static class Digest256 extends BCMessageDigest implements Cloneable {
        public Digest256() {
            super(new Haraka256Digest());
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Digest256 digest256 = (Digest256) super.clone();
            digest256.digest = new Haraka256Digest((Haraka256Digest) this.digest);
            return digest256;
        }
    }

    /* loaded from: classes2.dex */
    public static class Digest512 extends BCMessageDigest implements Cloneable {
        public Digest512() {
            super(new Haraka512Digest());
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Digest512 digest512 = (Digest512) super.clone();
            digest512.digest = new Haraka512Digest((Haraka512Digest) this.digest);
            return digest512;
        }
    }

    /* loaded from: classes2.dex */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Haraka.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            StringBuilder sb = new StringBuilder();
            String str = PREFIX;
            configurableProvider.addAlgorithm("MessageDigest.HARAKA-256", sb.append(str).append("$Digest256").toString());
            configurableProvider.addAlgorithm("MessageDigest.HARAKA-512", str + "$Digest512");
        }
    }

    private Haraka() {
    }
}