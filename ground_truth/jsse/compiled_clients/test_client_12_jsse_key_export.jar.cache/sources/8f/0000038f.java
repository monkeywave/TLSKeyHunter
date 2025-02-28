package org.bouncycastle.crypto;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/AsymmetricCipherKeyPairGenerator.class */
public interface AsymmetricCipherKeyPairGenerator {
    void init(KeyGenerationParameters keyGenerationParameters);

    AsymmetricCipherKeyPair generateKeyPair();
}