package org.openjsse.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.openjsse.sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/TlsRsaPremasterSecretGenerator.class */
public final class TlsRsaPremasterSecretGenerator extends KeyGeneratorSpi {
    private static final String MSG = "TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec";
    private TlsRsaPremasterSecretParameterSpec spec;
    private SecureRandom random;

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(params instanceof TlsRsaPremasterSecretParameterSpec)) {
            throw new InvalidAlgorithmParameterException(MSG);
        }
        this.spec = (TlsRsaPremasterSecretParameterSpec) params;
        this.random = random;
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(int keysize, SecureRandom random) {
        throw new InvalidParameterException(MSG);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected SecretKey engineGenerateKey() {
        if (this.spec == null) {
            throw new IllegalStateException("TlsRsaPremasterSecretGenerator must be initialized");
        }
        byte[] b = this.spec.getEncodedSecret();
        if (b == null) {
            if (this.random == null) {
                this.random = new SecureRandom();
            }
            b = new byte[48];
            this.random.nextBytes(b);
        }
        b[0] = (byte) this.spec.getMajorVersion();
        b[1] = (byte) this.spec.getMinorVersion();
        return new SecretKeySpec(b, "TlsRsaPremasterSecret");
    }
}