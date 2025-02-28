package org.bouncycastle.pqc.crypto.ntruprime;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class NTRULPRimeKeyGenerationParameters extends KeyGenerationParameters {
    private final NTRULPRimeParameters ntrulprParams;

    public NTRULPRimeKeyGenerationParameters(SecureRandom secureRandom, NTRULPRimeParameters nTRULPRimeParameters) {
        super(secureRandom == null ? CryptoServicesRegistrar.getSecureRandom() : secureRandom, 256);
        this.ntrulprParams = nTRULPRimeParameters;
    }

    public NTRULPRimeParameters getNtrulprParams() {
        return this.ntrulprParams;
    }
}