package org.bouncycastle.crypto.params;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ElGamalKeyGenerationParameters.class */
public class ElGamalKeyGenerationParameters extends KeyGenerationParameters {
    private ElGamalParameters params;

    public ElGamalKeyGenerationParameters(SecureRandom secureRandom, ElGamalParameters elGamalParameters) {
        super(secureRandom, getStrength(elGamalParameters));
        this.params = elGamalParameters;
    }

    public ElGamalParameters getParameters() {
        return this.params;
    }

    static int getStrength(ElGamalParameters elGamalParameters) {
        return elGamalParameters.getL() != 0 ? elGamalParameters.getL() : elGamalParameters.getP().bitLength();
    }
}