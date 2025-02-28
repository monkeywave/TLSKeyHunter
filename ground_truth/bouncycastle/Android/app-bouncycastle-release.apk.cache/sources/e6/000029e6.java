package org.bouncycastle.pqc.crypto.lms;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class LMSKeyGenerationParameters extends KeyGenerationParameters {
    private final LMSParameters lmsParameters;

    public LMSKeyGenerationParameters(LMSParameters lMSParameters, SecureRandom secureRandom) {
        super(secureRandom, LmsUtils.calculateStrength(lMSParameters));
        this.lmsParameters = lMSParameters;
    }

    public LMSParameters getParameters() {
        return this.lmsParameters;
    }
}