package org.bouncycastle.pqc.crypto.saber;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class SABERKeyGenerationParameters extends KeyGenerationParameters {
    private SABERParameters params;

    public SABERKeyGenerationParameters(SecureRandom secureRandom, SABERParameters sABERParameters) {
        super(secureRandom, 256);
        this.params = sABERParameters;
    }

    public SABERParameters getParameters() {
        return this.params;
    }
}