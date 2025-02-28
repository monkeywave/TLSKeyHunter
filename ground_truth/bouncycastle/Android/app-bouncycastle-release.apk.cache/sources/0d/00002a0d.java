package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class MLKEMKeyGenerationParameters extends KeyGenerationParameters {
    private final MLKEMParameters params;

    public MLKEMKeyGenerationParameters(SecureRandom secureRandom, MLKEMParameters mLKEMParameters) {
        super(secureRandom, 256);
        this.params = mLKEMParameters;
    }

    public MLKEMParameters getParameters() {
        return this.params;
    }
}