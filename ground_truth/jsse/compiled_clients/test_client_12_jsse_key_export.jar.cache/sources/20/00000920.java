package org.bouncycastle.jcajce.provider.digest;

import org.bouncycastle.asn1.iana.IANAObjectIdentifiers;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.symmetric.util.PBESecretKeyFactory;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger.class */
public class Tiger {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$Digest.class */
    public static class Digest extends BCMessageDigest implements Cloneable {
        public Digest() {
            super(new TigerDigest());
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            Digest digest = (Digest) super.clone();
            digest.digest = new TigerDigest((TigerDigest) this.digest);
            return digest;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$HashMac.class */
    public static class HashMac extends BaseMac {
        public HashMac() {
            super(new HMac(new TigerDigest()));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$KeyGenerator.class */
    public static class KeyGenerator extends BaseKeyGenerator {
        public KeyGenerator() {
            super("HMACTIGER", 192, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$Mappings.class */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Tiger.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("MessageDigest.TIGER", PREFIX + "$Digest");
            configurableProvider.addAlgorithm("MessageDigest.Tiger", PREFIX + "$Digest");
            addHMACAlgorithm(configurableProvider, "TIGER", PREFIX + "$HashMac", PREFIX + "$KeyGenerator");
            addHMACAlias(configurableProvider, "TIGER", IANAObjectIdentifiers.hmacTIGER);
            configurableProvider.addAlgorithm("SecretKeyFactory.PBEWITHHMACTIGER", PREFIX + "$PBEWithMacKeyFactory");
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$PBEWithHashMac.class */
    public static class PBEWithHashMac extends BaseMac {
        public PBEWithHashMac() {
            super(new HMac(new TigerDigest()), 2, 3, 192);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$PBEWithMacKeyFactory.class */
    public static class PBEWithMacKeyFactory extends PBESecretKeyFactory {
        public PBEWithMacKeyFactory() {
            super("PBEwithHmacTiger", null, false, 2, 3, 192, 0);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Tiger$TigerHmac.class */
    public static class TigerHmac extends BaseMac {
        public TigerHmac() {
            super(new HMac(new TigerDigest()));
        }
    }

    private Tiger() {
    }
}