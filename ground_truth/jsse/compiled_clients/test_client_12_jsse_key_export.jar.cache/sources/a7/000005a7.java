package org.bouncycastle.crypto.prng;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/RandomGenerator.class */
public interface RandomGenerator {
    void addSeedMaterial(byte[] bArr);

    void addSeedMaterial(long j);

    void nextBytes(byte[] bArr);

    void nextBytes(byte[] bArr, int i, int i2);
}