package org.bouncycastle.jcajce.provider.digest;

import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.BERTags;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.digests.SkeinDigest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.macs.SkeinMac;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein.class */
public class Skein {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$DigestSkein1024.class */
    public static class DigestSkein1024 extends BCMessageDigest implements Cloneable {
        public DigestSkein1024(int i) {
            super(new SkeinDigest(1024, i));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            BCMessageDigest bCMessageDigest = (BCMessageDigest) super.clone();
            bCMessageDigest.digest = new SkeinDigest((SkeinDigest) this.digest);
            return bCMessageDigest;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$DigestSkein256.class */
    public static class DigestSkein256 extends BCMessageDigest implements Cloneable {
        public DigestSkein256(int i) {
            super(new SkeinDigest(256, i));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            BCMessageDigest bCMessageDigest = (BCMessageDigest) super.clone();
            bCMessageDigest.digest = new SkeinDigest((SkeinDigest) this.digest);
            return bCMessageDigest;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$DigestSkein512.class */
    public static class DigestSkein512 extends BCMessageDigest implements Cloneable {
        public DigestSkein512(int i) {
            super(new SkeinDigest(512, i));
        }

        @Override // java.security.MessageDigest, java.security.MessageDigestSpi
        public Object clone() throws CloneNotSupportedException {
            BCMessageDigest bCMessageDigest = (BCMessageDigest) super.clone();
            bCMessageDigest.digest = new SkeinDigest((SkeinDigest) this.digest);
            return bCMessageDigest;
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_1024_1024.class */
    public static class Digest_1024_1024 extends DigestSkein1024 {
        public Digest_1024_1024() {
            super(1024);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_1024_384.class */
    public static class Digest_1024_384 extends DigestSkein1024 {
        public Digest_1024_384() {
            super(384);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_1024_512.class */
    public static class Digest_1024_512 extends DigestSkein1024 {
        public Digest_1024_512() {
            super(512);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_256_128.class */
    public static class Digest_256_128 extends DigestSkein256 {
        public Digest_256_128() {
            super(128);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_256_160.class */
    public static class Digest_256_160 extends DigestSkein256 {
        public Digest_256_160() {
            super(Opcode.IF_ICMPNE);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_256_224.class */
    public static class Digest_256_224 extends DigestSkein256 {
        public Digest_256_224() {
            super(BERTags.FLAGS);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_256_256.class */
    public static class Digest_256_256 extends DigestSkein256 {
        public Digest_256_256() {
            super(256);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_128.class */
    public static class Digest_512_128 extends DigestSkein512 {
        public Digest_512_128() {
            super(128);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_160.class */
    public static class Digest_512_160 extends DigestSkein512 {
        public Digest_512_160() {
            super(Opcode.IF_ICMPNE);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_224.class */
    public static class Digest_512_224 extends DigestSkein512 {
        public Digest_512_224() {
            super(BERTags.FLAGS);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_256.class */
    public static class Digest_512_256 extends DigestSkein512 {
        public Digest_512_256() {
            super(256);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_384.class */
    public static class Digest_512_384 extends DigestSkein512 {
        public Digest_512_384() {
            super(384);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Digest_512_512.class */
    public static class Digest_512_512 extends DigestSkein512 {
        public Digest_512_512() {
            super(512);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_1024_1024.class */
    public static class HMacKeyGenerator_1024_1024 extends BaseKeyGenerator {
        public HMacKeyGenerator_1024_1024() {
            super("HMACSkein-1024-1024", 1024, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_1024_384.class */
    public static class HMacKeyGenerator_1024_384 extends BaseKeyGenerator {
        public HMacKeyGenerator_1024_384() {
            super("HMACSkein-1024-384", 384, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_1024_512.class */
    public static class HMacKeyGenerator_1024_512 extends BaseKeyGenerator {
        public HMacKeyGenerator_1024_512() {
            super("HMACSkein-1024-512", 512, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_256_128.class */
    public static class HMacKeyGenerator_256_128 extends BaseKeyGenerator {
        public HMacKeyGenerator_256_128() {
            super("HMACSkein-256-128", 128, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_256_160.class */
    public static class HMacKeyGenerator_256_160 extends BaseKeyGenerator {
        public HMacKeyGenerator_256_160() {
            super("HMACSkein-256-160", Opcode.IF_ICMPNE, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_256_224.class */
    public static class HMacKeyGenerator_256_224 extends BaseKeyGenerator {
        public HMacKeyGenerator_256_224() {
            super("HMACSkein-256-224", BERTags.FLAGS, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_256_256.class */
    public static class HMacKeyGenerator_256_256 extends BaseKeyGenerator {
        public HMacKeyGenerator_256_256() {
            super("HMACSkein-256-256", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_128.class */
    public static class HMacKeyGenerator_512_128 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_128() {
            super("HMACSkein-512-128", 128, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_160.class */
    public static class HMacKeyGenerator_512_160 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_160() {
            super("HMACSkein-512-160", Opcode.IF_ICMPNE, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_224.class */
    public static class HMacKeyGenerator_512_224 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_224() {
            super("HMACSkein-512-224", BERTags.FLAGS, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_256.class */
    public static class HMacKeyGenerator_512_256 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_256() {
            super("HMACSkein-512-256", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_384.class */
    public static class HMacKeyGenerator_512_384 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_384() {
            super("HMACSkein-512-384", 384, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HMacKeyGenerator_512_512.class */
    public static class HMacKeyGenerator_512_512 extends BaseKeyGenerator {
        public HMacKeyGenerator_512_512() {
            super("HMACSkein-512-512", 512, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_1024_1024.class */
    public static class HashMac_1024_1024 extends BaseMac {
        public HashMac_1024_1024() {
            super(new HMac(new SkeinDigest(1024, 1024)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_1024_384.class */
    public static class HashMac_1024_384 extends BaseMac {
        public HashMac_1024_384() {
            super(new HMac(new SkeinDigest(1024, 384)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_1024_512.class */
    public static class HashMac_1024_512 extends BaseMac {
        public HashMac_1024_512() {
            super(new HMac(new SkeinDigest(1024, 512)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_256_128.class */
    public static class HashMac_256_128 extends BaseMac {
        public HashMac_256_128() {
            super(new HMac(new SkeinDigest(256, 128)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_256_160.class */
    public static class HashMac_256_160 extends BaseMac {
        public HashMac_256_160() {
            super(new HMac(new SkeinDigest(256, Opcode.IF_ICMPNE)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_256_224.class */
    public static class HashMac_256_224 extends BaseMac {
        public HashMac_256_224() {
            super(new HMac(new SkeinDigest(256, BERTags.FLAGS)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_256_256.class */
    public static class HashMac_256_256 extends BaseMac {
        public HashMac_256_256() {
            super(new HMac(new SkeinDigest(256, 256)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_128.class */
    public static class HashMac_512_128 extends BaseMac {
        public HashMac_512_128() {
            super(new HMac(new SkeinDigest(512, 128)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_160.class */
    public static class HashMac_512_160 extends BaseMac {
        public HashMac_512_160() {
            super(new HMac(new SkeinDigest(512, Opcode.IF_ICMPNE)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_224.class */
    public static class HashMac_512_224 extends BaseMac {
        public HashMac_512_224() {
            super(new HMac(new SkeinDigest(512, BERTags.FLAGS)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_256.class */
    public static class HashMac_512_256 extends BaseMac {
        public HashMac_512_256() {
            super(new HMac(new SkeinDigest(512, 256)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_384.class */
    public static class HashMac_512_384 extends BaseMac {
        public HashMac_512_384() {
            super(new HMac(new SkeinDigest(512, 384)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$HashMac_512_512.class */
    public static class HashMac_512_512 extends BaseMac {
        public HashMac_512_512() {
            super(new HMac(new SkeinDigest(512, 512)));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$Mappings.class */
    public static class Mappings extends DigestAlgorithmProvider {
        private static final String PREFIX = Skein.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("MessageDigest.Skein-256-128", PREFIX + "$Digest_256_128");
            configurableProvider.addAlgorithm("MessageDigest.Skein-256-160", PREFIX + "$Digest_256_160");
            configurableProvider.addAlgorithm("MessageDigest.Skein-256-224", PREFIX + "$Digest_256_224");
            configurableProvider.addAlgorithm("MessageDigest.Skein-256-256", PREFIX + "$Digest_256_256");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-128", PREFIX + "$Digest_512_128");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-160", PREFIX + "$Digest_512_160");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-224", PREFIX + "$Digest_512_224");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-256", PREFIX + "$Digest_512_256");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-384", PREFIX + "$Digest_512_384");
            configurableProvider.addAlgorithm("MessageDigest.Skein-512-512", PREFIX + "$Digest_512_512");
            configurableProvider.addAlgorithm("MessageDigest.Skein-1024-384", PREFIX + "$Digest_1024_384");
            configurableProvider.addAlgorithm("MessageDigest.Skein-1024-512", PREFIX + "$Digest_1024_512");
            configurableProvider.addAlgorithm("MessageDigest.Skein-1024-1024", PREFIX + "$Digest_1024_1024");
            addHMACAlgorithm(configurableProvider, "Skein-256-128", PREFIX + "$HashMac_256_128", PREFIX + "$HMacKeyGenerator_256_128");
            addHMACAlgorithm(configurableProvider, "Skein-256-160", PREFIX + "$HashMac_256_160", PREFIX + "$HMacKeyGenerator_256_160");
            addHMACAlgorithm(configurableProvider, "Skein-256-224", PREFIX + "$HashMac_256_224", PREFIX + "$HMacKeyGenerator_256_224");
            addHMACAlgorithm(configurableProvider, "Skein-256-256", PREFIX + "$HashMac_256_256", PREFIX + "$HMacKeyGenerator_256_256");
            addHMACAlgorithm(configurableProvider, "Skein-512-128", PREFIX + "$HashMac_512_128", PREFIX + "$HMacKeyGenerator_512_128");
            addHMACAlgorithm(configurableProvider, "Skein-512-160", PREFIX + "$HashMac_512_160", PREFIX + "$HMacKeyGenerator_512_160");
            addHMACAlgorithm(configurableProvider, "Skein-512-224", PREFIX + "$HashMac_512_224", PREFIX + "$HMacKeyGenerator_512_224");
            addHMACAlgorithm(configurableProvider, "Skein-512-256", PREFIX + "$HashMac_512_256", PREFIX + "$HMacKeyGenerator_512_256");
            addHMACAlgorithm(configurableProvider, "Skein-512-384", PREFIX + "$HashMac_512_384", PREFIX + "$HMacKeyGenerator_512_384");
            addHMACAlgorithm(configurableProvider, "Skein-512-512", PREFIX + "$HashMac_512_512", PREFIX + "$HMacKeyGenerator_512_512");
            addHMACAlgorithm(configurableProvider, "Skein-1024-384", PREFIX + "$HashMac_1024_384", PREFIX + "$HMacKeyGenerator_1024_384");
            addHMACAlgorithm(configurableProvider, "Skein-1024-512", PREFIX + "$HashMac_1024_512", PREFIX + "$HMacKeyGenerator_1024_512");
            addHMACAlgorithm(configurableProvider, "Skein-1024-1024", PREFIX + "$HashMac_1024_1024", PREFIX + "$HMacKeyGenerator_1024_1024");
            addSkeinMacAlgorithm(configurableProvider, 256, 128);
            addSkeinMacAlgorithm(configurableProvider, 256, Opcode.IF_ICMPNE);
            addSkeinMacAlgorithm(configurableProvider, 256, BERTags.FLAGS);
            addSkeinMacAlgorithm(configurableProvider, 256, 256);
            addSkeinMacAlgorithm(configurableProvider, 512, 128);
            addSkeinMacAlgorithm(configurableProvider, 512, Opcode.IF_ICMPNE);
            addSkeinMacAlgorithm(configurableProvider, 512, BERTags.FLAGS);
            addSkeinMacAlgorithm(configurableProvider, 512, 256);
            addSkeinMacAlgorithm(configurableProvider, 512, 384);
            addSkeinMacAlgorithm(configurableProvider, 512, 512);
            addSkeinMacAlgorithm(configurableProvider, 1024, 384);
            addSkeinMacAlgorithm(configurableProvider, 1024, 512);
            addSkeinMacAlgorithm(configurableProvider, 1024, 1024);
        }

        private void addSkeinMacAlgorithm(ConfigurableProvider configurableProvider, int i, int i2) {
            String str = "Skein-MAC-" + i + "-" + i2;
            configurableProvider.addAlgorithm("Mac." + str, PREFIX + "$SkeinMac_" + i + "_" + i2);
            configurableProvider.addAlgorithm("Alg.Alias.Mac.Skein-MAC" + i + "/" + i2, str);
            configurableProvider.addAlgorithm("KeyGenerator." + str, PREFIX + "$SkeinMacKeyGenerator_" + i + "_" + i2);
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator.Skein-MAC" + i + "/" + i2, str);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_1024_1024.class */
    public static class SkeinMacKeyGenerator_1024_1024 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_1024_1024() {
            super("Skein-MAC-1024-1024", 1024, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_1024_384.class */
    public static class SkeinMacKeyGenerator_1024_384 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_1024_384() {
            super("Skein-MAC-1024-384", 384, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_1024_512.class */
    public static class SkeinMacKeyGenerator_1024_512 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_1024_512() {
            super("Skein-MAC-1024-512", 512, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_256_128.class */
    public static class SkeinMacKeyGenerator_256_128 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_256_128() {
            super("Skein-MAC-256-128", 128, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_256_160.class */
    public static class SkeinMacKeyGenerator_256_160 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_256_160() {
            super("Skein-MAC-256-160", Opcode.IF_ICMPNE, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_256_224.class */
    public static class SkeinMacKeyGenerator_256_224 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_256_224() {
            super("Skein-MAC-256-224", BERTags.FLAGS, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_256_256.class */
    public static class SkeinMacKeyGenerator_256_256 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_256_256() {
            super("Skein-MAC-256-256", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_128.class */
    public static class SkeinMacKeyGenerator_512_128 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_128() {
            super("Skein-MAC-512-128", 128, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_160.class */
    public static class SkeinMacKeyGenerator_512_160 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_160() {
            super("Skein-MAC-512-160", Opcode.IF_ICMPNE, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_224.class */
    public static class SkeinMacKeyGenerator_512_224 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_224() {
            super("Skein-MAC-512-224", BERTags.FLAGS, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_256.class */
    public static class SkeinMacKeyGenerator_512_256 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_256() {
            super("Skein-MAC-512-256", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_384.class */
    public static class SkeinMacKeyGenerator_512_384 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_384() {
            super("Skein-MAC-512-384", 384, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMacKeyGenerator_512_512.class */
    public static class SkeinMacKeyGenerator_512_512 extends BaseKeyGenerator {
        public SkeinMacKeyGenerator_512_512() {
            super("Skein-MAC-512-512", 512, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_1024_1024.class */
    public static class SkeinMac_1024_1024 extends BaseMac {
        public SkeinMac_1024_1024() {
            super(new SkeinMac(1024, 1024));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_1024_384.class */
    public static class SkeinMac_1024_384 extends BaseMac {
        public SkeinMac_1024_384() {
            super(new SkeinMac(1024, 384));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_1024_512.class */
    public static class SkeinMac_1024_512 extends BaseMac {
        public SkeinMac_1024_512() {
            super(new SkeinMac(1024, 512));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_256_128.class */
    public static class SkeinMac_256_128 extends BaseMac {
        public SkeinMac_256_128() {
            super(new SkeinMac(256, 128));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_256_160.class */
    public static class SkeinMac_256_160 extends BaseMac {
        public SkeinMac_256_160() {
            super(new SkeinMac(256, Opcode.IF_ICMPNE));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_256_224.class */
    public static class SkeinMac_256_224 extends BaseMac {
        public SkeinMac_256_224() {
            super(new SkeinMac(256, BERTags.FLAGS));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_256_256.class */
    public static class SkeinMac_256_256 extends BaseMac {
        public SkeinMac_256_256() {
            super(new SkeinMac(256, 256));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_128.class */
    public static class SkeinMac_512_128 extends BaseMac {
        public SkeinMac_512_128() {
            super(new SkeinMac(512, 128));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_160.class */
    public static class SkeinMac_512_160 extends BaseMac {
        public SkeinMac_512_160() {
            super(new SkeinMac(512, Opcode.IF_ICMPNE));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_224.class */
    public static class SkeinMac_512_224 extends BaseMac {
        public SkeinMac_512_224() {
            super(new SkeinMac(512, BERTags.FLAGS));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_256.class */
    public static class SkeinMac_512_256 extends BaseMac {
        public SkeinMac_512_256() {
            super(new SkeinMac(512, 256));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_384.class */
    public static class SkeinMac_512_384 extends BaseMac {
        public SkeinMac_512_384() {
            super(new SkeinMac(512, 384));
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/digest/Skein$SkeinMac_512_512.class */
    public static class SkeinMac_512_512 extends BaseMac {
        public SkeinMac_512_512() {
            super(new SkeinMac(512, 512));
        }
    }

    private Skein() {
    }
}