package org.bouncycastle.jcajce.provider.asymmetric;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;
import org.bouncycastle.jcajce.spec.ContextParameterSpec;

/* loaded from: classes2.dex */
public class CONTEXT {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.CONTEXT$";

    /* loaded from: classes2.dex */
    public static class ContextAlgorithmParametersSpi extends AlgorithmParametersSpi {
        private ContextParameterSpec contextParameterSpec;

        @Override // java.security.AlgorithmParametersSpi
        protected byte[] engineGetEncoded() throws IOException {
            throw new IllegalStateException("not implemented");
        }

        @Override // java.security.AlgorithmParametersSpi
        protected byte[] engineGetEncoded(String str) throws IOException {
            throw new IllegalStateException("not implemented");
        }

        @Override // java.security.AlgorithmParametersSpi
        protected AlgorithmParameterSpec engineGetParameterSpec(Class cls) throws InvalidParameterSpecException {
            if (cls != null) {
                if (cls == ContextParameterSpec.class) {
                    return this.contextParameterSpec;
                }
                throw new IllegalArgumentException("argument to getParameterSpec must be ContextParameterSpec.class");
            }
            throw new NullPointerException("argument to getParameterSpec must not be null");
        }

        @Override // java.security.AlgorithmParametersSpi
        protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec) throws InvalidParameterSpecException {
            if (!(algorithmParameterSpec instanceof ContextParameterSpec)) {
                throw new IllegalArgumentException("argument to engineInit must be a ContextParameterSpec");
            }
            this.contextParameterSpec = (ContextParameterSpec) algorithmParameterSpec;
        }

        @Override // java.security.AlgorithmParametersSpi
        protected void engineInit(byte[] bArr) throws IOException {
            throw new IllegalStateException("not implemented");
        }

        @Override // java.security.AlgorithmParametersSpi
        protected void engineInit(byte[] bArr, String str) throws IOException {
            throw new IllegalStateException("not implemented");
        }

        @Override // java.security.AlgorithmParametersSpi
        protected String engineToString() {
            return "ContextParameterSpec";
        }

        protected boolean isASN1FormatString(String str) {
            return str == null || str.equals("ASN.1");
        }
    }

    /* loaded from: classes2.dex */
    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            configurableProvider.addAlgorithm("AlgorithmParameters.CONTEXT", "org.bouncycastle.jcajce.provider.asymmetric.CONTEXT$ContextAlgorithmParametersSpi");
        }
    }
}