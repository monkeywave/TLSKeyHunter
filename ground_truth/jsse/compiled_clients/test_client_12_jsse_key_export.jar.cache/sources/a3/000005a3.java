package org.bouncycastle.crypto.prng;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/EntropySource.class */
public interface EntropySource {
    boolean isPredictionResistant();

    byte[] getEntropy();

    int entropySize();
}