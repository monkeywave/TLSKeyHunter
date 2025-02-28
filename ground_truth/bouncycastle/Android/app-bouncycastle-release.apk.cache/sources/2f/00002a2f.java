package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class NTRUKeyGenerationParameters extends KeyGenerationParameters {
    private final NTRUParameters ntruParameters;

    public NTRUKeyGenerationParameters(SecureRandom secureRandom, NTRUParameters nTRUParameters) {
        super(secureRandom, 0);
        this.ntruParameters = nTRUParameters;
    }

    public NTRUParameters getParameters() {
        return this.ntruParameters;
    }
}