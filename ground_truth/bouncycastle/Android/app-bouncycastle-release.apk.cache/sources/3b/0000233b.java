package org.bouncycastle.jcajce.provider.drbg;

import java.security.SecureRandom;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class IncrementalEntropySourceProvider implements EntropySourceProvider {
    private final boolean predictionResistant;
    private final SecureRandom random;

    public IncrementalEntropySourceProvider(SecureRandom secureRandom, boolean z) {
        this.random = secureRandom;
        this.predictionResistant = z;
    }

    /* JADX INFO: Access modifiers changed from: private */
    public static void sleep(long j) throws InterruptedException {
        if (j != 0) {
            Thread.sleep(j);
        }
    }

    @Override // org.bouncycastle.crypto.prng.EntropySourceProvider
    public EntropySource get(int i) {
        return new IncrementalEntropySource(i) { // from class: org.bouncycastle.jcajce.provider.drbg.IncrementalEntropySourceProvider.1
            final int numBytes;
            final /* synthetic */ int val$bitsRequired;

            {
                this.val$bitsRequired = i;
                this.numBytes = (i + 7) / 8;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public int entropySize() {
                return this.val$bitsRequired;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public byte[] getEntropy() {
                try {
                    return getEntropy(0L);
                } catch (InterruptedException unused) {
                    Thread.currentThread().interrupt();
                    throw new IllegalStateException("initial entropy fetch interrupted");
                }
            }

            @Override // org.bouncycastle.jcajce.provider.drbg.IncrementalEntropySource
            public byte[] getEntropy(long j) throws InterruptedException {
                int i2;
                int i3 = this.numBytes;
                byte[] bArr = new byte[i3];
                int i4 = 0;
                while (true) {
                    i2 = this.numBytes;
                    if (i4 >= i2 / 8) {
                        break;
                    }
                    IncrementalEntropySourceProvider.sleep(j);
                    byte[] generateSeed = IncrementalEntropySourceProvider.this.random.generateSeed(8);
                    System.arraycopy(generateSeed, 0, bArr, i4 * 8, generateSeed.length);
                    i4++;
                }
                int i5 = i2 - ((i2 / 8) * 8);
                if (i5 != 0) {
                    IncrementalEntropySourceProvider.sleep(j);
                    byte[] generateSeed2 = IncrementalEntropySourceProvider.this.random.generateSeed(i5);
                    System.arraycopy(generateSeed2, 0, bArr, i3 - generateSeed2.length, generateSeed2.length);
                }
                return bArr;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public boolean isPredictionResistant() {
                return IncrementalEntropySourceProvider.this.predictionResistant;
            }
        };
    }
}