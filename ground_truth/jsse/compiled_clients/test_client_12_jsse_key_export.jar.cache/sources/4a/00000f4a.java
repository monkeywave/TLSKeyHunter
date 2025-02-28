package org.openjsse.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/ChaCha20KeyGenerator.class */
public final class ChaCha20KeyGenerator extends KeyGeneratorSpi {
    private final KeyGeneratorCore core = new KeyGeneratorCore("ChaCha20", 256);

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(SecureRandom random) {
        this.core.implInit(random);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        this.core.implInit(params, random);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected void engineInit(int keySize, SecureRandom random) {
        if (keySize != 256) {
            throw new InvalidParameterException("Key length for ChaCha20 must be 256 bits");
        }
        this.core.implInit(keySize, random);
    }

    @Override // javax.crypto.KeyGeneratorSpi
    protected SecretKey engineGenerateKey() {
        return this.core.implGenerateKey();
    }
}