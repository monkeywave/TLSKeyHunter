package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.params.ElGamalParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/ElGamalParametersGenerator.class */
public class ElGamalParametersGenerator {
    private int size;
    private int certainty;
    private SecureRandom random;

    public void init(int i, int i2, SecureRandom secureRandom) {
        this.size = i;
        this.certainty = i2;
        this.random = secureRandom;
    }

    public ElGamalParameters generateParameters() {
        BigInteger[] generateSafePrimes = DHParametersHelper.generateSafePrimes(this.size, this.certainty, this.random);
        BigInteger bigInteger = generateSafePrimes[0];
        return new ElGamalParameters(bigInteger, DHParametersHelper.selectGenerator(bigInteger, generateSafePrimes[1], this.random));
    }
}