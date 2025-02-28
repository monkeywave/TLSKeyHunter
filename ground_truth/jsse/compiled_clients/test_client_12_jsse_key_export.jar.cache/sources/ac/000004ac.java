package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.CramerShoupParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/CramerShoupParametersGenerator.class */
public class CramerShoupParametersGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private int size;
    private int certainty;
    private SecureRandom random;

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/CramerShoupParametersGenerator$ParametersHelper.class */
    private static class ParametersHelper {
        private static final BigInteger TWO = BigInteger.valueOf(2);

        private ParametersHelper() {
        }

        static BigInteger[] generateSafePrimes(int i, int i2, SecureRandom secureRandom) {
            BigInteger createRandomPrime;
            BigInteger add;
            int i3 = i - 1;
            while (true) {
                createRandomPrime = BigIntegers.createRandomPrime(i3, 2, secureRandom);
                add = createRandomPrime.shiftLeft(1).add(CramerShoupParametersGenerator.ONE);
                if (!add.isProbablePrime(i2) || (i2 > 2 && !createRandomPrime.isProbablePrime(i2))) {
                }
            }
            return new BigInteger[]{add, createRandomPrime};
        }

        static BigInteger selectGenerator(BigInteger bigInteger, SecureRandom secureRandom) {
            BigInteger modPow;
            BigInteger subtract = bigInteger.subtract(TWO);
            do {
                modPow = BigIntegers.createRandomInRange(TWO, subtract, secureRandom).modPow(TWO, bigInteger);
            } while (modPow.equals(CramerShoupParametersGenerator.ONE));
            return modPow;
        }
    }

    public void init(int i, int i2, SecureRandom secureRandom) {
        this.size = i;
        this.certainty = i2;
        this.random = secureRandom;
    }

    public CramerShoupParameters generateParameters() {
        BigInteger bigInteger = ParametersHelper.generateSafePrimes(this.size, this.certainty, this.random)[1];
        BigInteger selectGenerator = ParametersHelper.selectGenerator(bigInteger, this.random);
        BigInteger selectGenerator2 = ParametersHelper.selectGenerator(bigInteger, this.random);
        while (true) {
            BigInteger bigInteger2 = selectGenerator2;
            if (!selectGenerator.equals(bigInteger2)) {
                return new CramerShoupParameters(bigInteger, selectGenerator, bigInteger2, new SHA256Digest());
            }
            selectGenerator2 = ParametersHelper.selectGenerator(bigInteger, this.random);
        }
    }

    public CramerShoupParameters generateParameters(DHParameters dHParameters) {
        BigInteger p = dHParameters.getP();
        BigInteger g = dHParameters.getG();
        BigInteger selectGenerator = ParametersHelper.selectGenerator(p, this.random);
        while (true) {
            BigInteger bigInteger = selectGenerator;
            if (!g.equals(bigInteger)) {
                return new CramerShoupParameters(p, g, bigInteger, new SHA256Digest());
            }
            selectGenerator = ParametersHelper.selectGenerator(p, this.random);
        }
    }
}