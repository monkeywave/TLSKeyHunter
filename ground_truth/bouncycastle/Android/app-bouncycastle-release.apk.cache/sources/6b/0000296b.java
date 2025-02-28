package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class DilithiumKeyGenerationParameters extends KeyGenerationParameters {
    private final DilithiumParameters params;

    public DilithiumKeyGenerationParameters(SecureRandom secureRandom, DilithiumParameters dilithiumParameters) {
        super(secureRandom, 256);
        this.params = dilithiumParameters;
    }

    public DilithiumParameters getParameters() {
        return this.params;
    }
}