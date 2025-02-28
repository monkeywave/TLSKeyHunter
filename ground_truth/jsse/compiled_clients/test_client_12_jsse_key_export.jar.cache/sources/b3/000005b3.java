package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/X931SecureRandom.class */
public class X931SecureRandom extends SecureRandom {
    private final boolean predictionResistant;
    private final SecureRandom randomSource;
    private final X931RNG drbg;

    /* JADX INFO: Access modifiers changed from: package-private */
    public X931SecureRandom(SecureRandom secureRandom, X931RNG x931rng, boolean z) {
        this.randomSource = secureRandom;
        this.drbg = x931rng;
        this.predictionResistant = z;
    }

    @Override // java.security.SecureRandom
    public void setSeed(byte[] bArr) {
        synchronized (this) {
            if (this.randomSource != null) {
                this.randomSource.setSeed(bArr);
            }
        }
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void setSeed(long j) {
        synchronized (this) {
            if (this.randomSource != null) {
                this.randomSource.setSeed(j);
            }
        }
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void nextBytes(byte[] bArr) {
        synchronized (this) {
            if (this.drbg.generate(bArr, this.predictionResistant) < 0) {
                this.drbg.reseed();
                this.drbg.generate(bArr, this.predictionResistant);
            }
        }
    }

    @Override // java.security.SecureRandom
    public byte[] generateSeed(int i) {
        return EntropyUtil.generateSeed(this.drbg.getEntropySource(), i);
    }
}