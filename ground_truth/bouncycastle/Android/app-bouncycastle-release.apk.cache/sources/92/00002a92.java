package org.bouncycastle.pqc.crypto.slhdsa;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public class SLHDSAKeyGenerationParameters extends KeyGenerationParameters {
    private final SLHDSAParameters parameters;

    public SLHDSAKeyGenerationParameters(SecureRandom secureRandom, SLHDSAParameters sLHDSAParameters) {
        super(secureRandom, -1);
        this.parameters = sLHDSAParameters;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SLHDSAParameters getParameters() {
        return this.parameters;
    }
}