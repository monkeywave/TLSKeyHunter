package org.bouncycastle.pqc.crypto.mldsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class MLDSAKeyGenerationParameters extends KeyGenerationParameters {
    private final MLDSAParameters params;

    public MLDSAKeyGenerationParameters(SecureRandom secureRandom, MLDSAParameters mLDSAParameters) {
        super(secureRandom, 256);
        this.params = mLDSAParameters;
    }

    public MLDSAParameters getParameters() {
        return this.params;
    }
}