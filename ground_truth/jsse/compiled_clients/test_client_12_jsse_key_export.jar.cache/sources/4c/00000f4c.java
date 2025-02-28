package org.openjsse.com.sun.crypto.provider;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/KeyGeneratorCore.class */
final class KeyGeneratorCore {
    private final String name;
    private final int defaultKeySize;
    private int keySize;
    private SecureRandom random;

    /* JADX INFO: Access modifiers changed from: package-private */
    public KeyGeneratorCore(String name, int defaultKeySize) {
        this.name = name;
        this.defaultKeySize = defaultKeySize;
        implInit(null);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void implInit(SecureRandom random) {
        this.keySize = this.defaultKeySize;
        this.random = random;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void implInit(AlgorithmParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(this.name + " key generation does not take any parameters");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void implInit(int keysize, SecureRandom random) {
        if (keysize < 40) {
            throw new InvalidParameterException("Key length must be at least 40 bits");
        }
        this.keySize = keysize;
        this.random = random;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecretKey implGenerateKey() {
        if (this.random == null) {
            this.random = new SecureRandom();
        }
        byte[] b = new byte[(this.keySize + 7) >> 3];
        this.random.nextBytes(b);
        return new SecretKeySpec(b, this.name);
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/crypto/provider/KeyGeneratorCore$ChaCha20KeyGenerator.class */
    public static final class ChaCha20KeyGenerator extends KeyGeneratorSpi {
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
}