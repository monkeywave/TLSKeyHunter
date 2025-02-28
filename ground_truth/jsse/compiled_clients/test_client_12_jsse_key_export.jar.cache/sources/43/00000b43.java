package org.bouncycastle.jcajce.provider.symmetric;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.XSalsa20Engine;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseKeyGenerator;
import org.bouncycastle.jcajce.provider.symmetric.util.BaseStreamCipher;
import org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters;
import org.bouncycastle.jcajce.provider.util.AlgorithmProvider;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/XSalsa20.class */
public final class XSalsa20 {

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/XSalsa20$AlgParams.class */
    public static class AlgParams extends IvAlgorithmParameters {
        @Override // org.bouncycastle.jcajce.provider.symmetric.util.IvAlgorithmParameters, java.security.AlgorithmParametersSpi
        protected String engineToString() {
            return "XSalsa20 IV";
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/XSalsa20$Base.class */
    public static class Base extends BaseStreamCipher {
        public Base() {
            super(new XSalsa20Engine(), 24);
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/XSalsa20$KeyGen.class */
    public static class KeyGen extends BaseKeyGenerator {
        public KeyGen() {
            super("XSalsa20", 256, new CipherKeyGenerator());
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/symmetric/XSalsa20$Mappings.class */
    public static class Mappings extends AlgorithmProvider {
        private static final String PREFIX = XSalsa20.class.getName();

        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("Cipher.XSALSA20", PREFIX + "$Base");
            configurableProvider.addAlgorithm("KeyGenerator.XSALSA20", PREFIX + "$KeyGen");
            configurableProvider.addAlgorithm("AlgorithmParameters.XSALSA20", PREFIX + "$AlgParams");
        }
    }

    private XSalsa20() {
    }
}