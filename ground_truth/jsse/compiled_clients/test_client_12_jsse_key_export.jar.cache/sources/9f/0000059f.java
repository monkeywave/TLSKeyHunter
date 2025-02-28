package org.bouncycastle.crypto.prng;

import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/BasicEntropySourceProvider.class */
public class BasicEntropySourceProvider implements EntropySourceProvider {
    private final SecureRandom _sr;
    private final boolean _predictionResistant;

    public BasicEntropySourceProvider(SecureRandom secureRandom, boolean z) {
        this._sr = secureRandom;
        this._predictionResistant = z;
    }

    @Override // org.bouncycastle.crypto.prng.EntropySourceProvider
    public EntropySource get(final int i) {
        return new EntropySource() { // from class: org.bouncycastle.crypto.prng.BasicEntropySourceProvider.1
            @Override // org.bouncycastle.crypto.prng.EntropySource
            public boolean isPredictionResistant() {
                return BasicEntropySourceProvider.this._predictionResistant;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public byte[] getEntropy() {
                if ((BasicEntropySourceProvider.this._sr instanceof SP800SecureRandom) || (BasicEntropySourceProvider.this._sr instanceof X931SecureRandom)) {
                    byte[] bArr = new byte[(i + 7) / 8];
                    BasicEntropySourceProvider.this._sr.nextBytes(bArr);
                    return bArr;
                }
                return BasicEntropySourceProvider.this._sr.generateSeed((i + 7) / 8);
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public int entropySize() {
                return i;
            }
        };
    }
}