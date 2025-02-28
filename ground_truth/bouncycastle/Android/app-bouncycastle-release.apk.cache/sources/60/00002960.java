package org.bouncycastle.pqc.crypto.cmce;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class CMCEKeyGenerationParameters extends KeyGenerationParameters {
    private CMCEParameters params;

    public CMCEKeyGenerationParameters(SecureRandom secureRandom, CMCEParameters cMCEParameters) {
        super(secureRandom, 256);
        this.params = cMCEParameters;
    }

    public CMCEParameters getParameters() {
        return this.params;
    }
}