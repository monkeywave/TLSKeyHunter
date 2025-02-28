package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;
import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

/* loaded from: classes2.dex */
public class SP800SecureRandom extends SecureRandom {
    private SP80090DRBG drbg;
    private final DRBGProvider drbgProvider;
    private final EntropySource entropySource;
    private final boolean predictionResistant;
    private final SecureRandom randomSource;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SP800SecureRandom(SecureRandom secureRandom, EntropySource entropySource, DRBGProvider dRBGProvider, boolean z) {
        this.randomSource = secureRandom;
        this.entropySource = entropySource;
        this.drbgProvider = dRBGProvider;
        this.predictionResistant = z;
    }

    @Override // java.security.SecureRandom
    public byte[] generateSeed(int i) {
        return EntropyUtil.generateSeed(this.entropySource, i);
    }

    @Override // java.security.SecureRandom
    public String getAlgorithm() {
        return this.drbgProvider.getAlgorithm();
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void nextBytes(byte[] bArr) {
        synchronized (this) {
            if (this.drbg == null) {
                this.drbg = this.drbgProvider.get(this.entropySource);
            }
            if (this.drbg.generate(bArr, null, this.predictionResistant) < 0) {
                this.drbg.reseed(null);
                this.drbg.generate(bArr, null, this.predictionResistant);
            }
        }
    }

    public void reseed(byte[] bArr) {
        synchronized (this) {
            if (this.drbg == null) {
                this.drbg = this.drbgProvider.get(this.entropySource);
            }
            this.drbg.reseed(bArr);
        }
    }

    @Override // java.security.SecureRandom, java.util.Random
    public void setSeed(long j) {
        synchronized (this) {
            SecureRandom secureRandom = this.randomSource;
            if (secureRandom != null) {
                secureRandom.setSeed(j);
            }
        }
    }

    @Override // java.security.SecureRandom
    public void setSeed(byte[] bArr) {
        synchronized (this) {
            SecureRandom secureRandom = this.randomSource;
            if (secureRandom != null) {
                secureRandom.setSeed(bArr);
            }
        }
    }
}