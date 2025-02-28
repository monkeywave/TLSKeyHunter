package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseMac;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

/* loaded from: classes2.dex */
public final class SipHash128 {

    /* loaded from: classes2.dex */
    public static class KeyGen extends BaseKeyGenerator {
        public KeyGen() {
            super("SipHash128", 128, new CipherKeyGenerator());
        }
    }

    /* loaded from: classes2.dex */
    public static class Mac24 extends BaseMac {
        public Mac24() {
            super(new org.bouncycastle.crypto.macs.SipHash128());
        }
    }

    /* loaded from: classes2.dex */
    public static class Mac48 extends BaseMac {
        public Mac48() {
            super(new org.bouncycastle.crypto.macs.SipHash128(4, 8));
        }
    }

    /* loaded from: classes2.dex */
    public static class Mappings extends AlgorithmProvider {
        private static final String PREFIX = SipHash128.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            StringBuilder sb = new StringBuilder();
            String str = PREFIX;
            configurableProvider.addAlgorithm("Mac.SIPHASH128-2-4", sb.append(str).append("$Mac24").toString());
            configurableProvider.addAlgorithm("Alg.Alias.Mac.SIPHASH128", "SIPHASH128-2-4");
            configurableProvider.addAlgorithm("Mac.SIPHASH128-4-8", str + "$Mac48");
            configurableProvider.addAlgorithm("KeyGenerator.SIPHASH128", str + "$KeyGen");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH128-2-4", "SIPHASH128");
            configurableProvider.addAlgorithm("Alg.Alias.KeyGenerator.SIPHASH128-4-8", "SIPHASH128");
        }
    }

    private SipHash128() {
    }
}