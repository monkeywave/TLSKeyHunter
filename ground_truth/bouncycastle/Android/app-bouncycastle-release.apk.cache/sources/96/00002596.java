package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class KTSParameterSpec extends KEMKDFSpec implements AlgorithmParameterSpec {
    private final AlgorithmParameterSpec parameterSpec;

    /* loaded from: classes2.dex */
    public static final class Builder {
        private final String algorithmName;
        private AlgorithmIdentifier kdfAlgorithm;
        private final int keySizeInBits;
        private byte[] otherInfo;
        private AlgorithmParameterSpec parameterSpec;

        public Builder(String str, int i) {
            this(str, i, null);
        }

        public Builder(String str, int i, byte[] bArr) {
            this.algorithmName = str;
            this.keySizeInBits = i;
            this.kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
            this.otherInfo = bArr == null ? new byte[0] : Arrays.clone(bArr);
        }

        public KTSParameterSpec build() {
            return new KTSParameterSpec(this.algorithmName, this.keySizeInBits, this.parameterSpec, this.kdfAlgorithm, this.otherInfo);
        }

        public Builder withKdfAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
            if (algorithmIdentifier != null) {
                this.kdfAlgorithm = algorithmIdentifier;
                return this;
            }
            throw new NullPointerException("kdfAlgorithm cannot be null");
        }

        public Builder withNoKdf() {
            this.kdfAlgorithm = null;
            return this;
        }

        public Builder withParameterSpec(AlgorithmParameterSpec algorithmParameterSpec) {
            this.parameterSpec = algorithmParameterSpec;
            return this;
        }
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public KTSParameterSpec(String str, int i, AlgorithmParameterSpec algorithmParameterSpec, AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        super(algorithmIdentifier, bArr, str, i);
        this.parameterSpec = algorithmParameterSpec;
    }

    public AlgorithmParameterSpec getParameterSpec() {
        return this.parameterSpec;
    }
}