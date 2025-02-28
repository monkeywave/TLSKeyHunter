package org.bouncycastle.jcajce.spec;

import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.p009x9.X9ObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class KEMGenerateSpec extends KEMKDFSpec implements AlgorithmParameterSpec {
    private final PublicKey publicKey;
    private static final byte[] EMPTY_OTHER_INFO = new byte[0];
    private static AlgorithmIdentifier DefKdf = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));

    /* loaded from: classes2.dex */
    public static final class Builder {
        private final String algorithmName;
        private final int keySizeInBits;
        private final PublicKey publicKey;
        private AlgorithmIdentifier kdfAlgorithm = new AlgorithmIdentifier(X9ObjectIdentifiers.id_kdf_kdf3, new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256));
        private byte[] otherInfo = KEMGenerateSpec.EMPTY_OTHER_INFO;

        public Builder(PublicKey publicKey, String str, int i) {
            this.publicKey = publicKey;
            this.algorithmName = str;
            this.keySizeInBits = i;
        }

        public KEMGenerateSpec build() {
            return new KEMGenerateSpec(this.publicKey, this.algorithmName, this.keySizeInBits, this.kdfAlgorithm, this.otherInfo);
        }

        public Builder withKdfAlgorithm(AlgorithmIdentifier algorithmIdentifier) {
            this.kdfAlgorithm = algorithmIdentifier;
            return this;
        }

        public Builder withNoKdf() {
            this.kdfAlgorithm = null;
            return this;
        }

        public Builder withOtherInfo(byte[] bArr) {
            this.otherInfo = bArr == null ? KEMGenerateSpec.EMPTY_OTHER_INFO : Arrays.clone(bArr);
            return this;
        }
    }

    public KEMGenerateSpec(PublicKey publicKey, String str) {
        this(publicKey, str, 256, DefKdf, EMPTY_OTHER_INFO);
    }

    public KEMGenerateSpec(PublicKey publicKey, String str, int i) {
        this(publicKey, str, i, DefKdf, EMPTY_OTHER_INFO);
    }

    private KEMGenerateSpec(PublicKey publicKey, String str, int i, AlgorithmIdentifier algorithmIdentifier, byte[] bArr) {
        super(algorithmIdentifier, bArr, str, i);
        this.publicKey = publicKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }
}