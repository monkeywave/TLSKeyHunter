package org.bouncycastle.util.test;

import java.security.SecureRandom;
import org.bouncycastle.crypto.prng.EntropySource;
import org.bouncycastle.crypto.prng.EntropySourceProvider;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/test/TestRandomEntropySourceProvider.class */
public class TestRandomEntropySourceProvider implements EntropySourceProvider {
    private final SecureRandom _sr = new SecureRandom();
    private final boolean _predictionResistant;

    public TestRandomEntropySourceProvider(boolean z) {
        this._predictionResistant = z;
    }

    @Override // org.bouncycastle.crypto.prng.EntropySourceProvider
    public EntropySource get(final int i) {
        return new EntropySource() { // from class: org.bouncycastle.util.test.TestRandomEntropySourceProvider.1
            @Override // org.bouncycastle.crypto.prng.EntropySource
            public boolean isPredictionResistant() {
                return TestRandomEntropySourceProvider.this._predictionResistant;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public byte[] getEntropy() {
                byte[] bArr = new byte[(i + 7) / 8];
                TestRandomEntropySourceProvider.this._sr.nextBytes(bArr);
                return bArr;
            }

            @Override // org.bouncycastle.crypto.prng.EntropySource
            public int entropySize() {
                return i;
            }
        };
    }
}