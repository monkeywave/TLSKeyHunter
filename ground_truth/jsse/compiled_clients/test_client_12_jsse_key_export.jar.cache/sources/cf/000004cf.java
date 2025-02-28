package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.math.Primes;
import org.bouncycastle.math.p010ec.WNafUtil;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/RSAKeyPairGenerator.class */
public class RSAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private RSAKeyGenerationParameters param;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (RSAKeyGenerationParameters) keyGenerationParameters;
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger chooseRandomPrime;
        BigInteger multiply;
        AsymmetricCipherKeyPair asymmetricCipherKeyPair = null;
        boolean z = false;
        int strength = this.param.getStrength();
        int i = (strength + 1) / 2;
        int i2 = strength - i;
        int i3 = (strength / 2) - 100;
        if (i3 < strength / 3) {
            i3 = strength / 3;
        }
        int i4 = strength >> 2;
        BigInteger pow = BigInteger.valueOf(2L).pow(strength / 2);
        BigInteger shiftLeft = ONE.shiftLeft(strength - 1);
        BigInteger shiftLeft2 = ONE.shiftLeft(i3);
        while (!z) {
            BigInteger publicExponent = this.param.getPublicExponent();
            BigInteger chooseRandomPrime2 = chooseRandomPrime(i, publicExponent, shiftLeft);
            while (true) {
                chooseRandomPrime = chooseRandomPrime(i2, publicExponent, shiftLeft);
                BigInteger abs = chooseRandomPrime.subtract(chooseRandomPrime2).abs();
                if (abs.bitLength() >= i3 && abs.compareTo(shiftLeft2) > 0) {
                    multiply = chooseRandomPrime2.multiply(chooseRandomPrime);
                    if (multiply.bitLength() == strength) {
                        if (WNafUtil.getNafWeight(multiply) >= i4) {
                            break;
                        }
                        chooseRandomPrime2 = chooseRandomPrime(i, publicExponent, shiftLeft);
                    } else {
                        chooseRandomPrime2 = chooseRandomPrime2.max(chooseRandomPrime);
                    }
                }
            }
            if (chooseRandomPrime2.compareTo(chooseRandomPrime) < 0) {
                BigInteger bigInteger = chooseRandomPrime2;
                chooseRandomPrime2 = chooseRandomPrime;
                chooseRandomPrime = bigInteger;
            }
            BigInteger subtract = chooseRandomPrime2.subtract(ONE);
            BigInteger subtract2 = chooseRandomPrime.subtract(ONE);
            BigInteger modInverse = publicExponent.modInverse(subtract.divide(subtract.gcd(subtract2)).multiply(subtract2));
            if (modInverse.compareTo(pow) > 0) {
                z = true;
                asymmetricCipherKeyPair = new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new RSAKeyParameters(false, multiply, publicExponent), (AsymmetricKeyParameter) new RSAPrivateCrtKeyParameters(multiply, publicExponent, modInverse, chooseRandomPrime2, chooseRandomPrime, modInverse.remainder(subtract), modInverse.remainder(subtract2), BigIntegers.modOddInverse(chooseRandomPrime2, chooseRandomPrime)));
            }
        }
        return asymmetricCipherKeyPair;
    }

    protected BigInteger chooseRandomPrime(int i, BigInteger bigInteger, BigInteger bigInteger2) {
        for (int i2 = 0; i2 != 5 * i; i2++) {
            BigInteger createRandomPrime = BigIntegers.createRandomPrime(i, 1, this.param.getRandom());
            if (!createRandomPrime.mod(bigInteger).equals(ONE) && createRandomPrime.multiply(createRandomPrime).compareTo(bigInteger2) >= 0 && isProbablePrime(createRandomPrime) && bigInteger.gcd(createRandomPrime.subtract(ONE)).equals(ONE)) {
                return createRandomPrime;
            }
        }
        throw new IllegalStateException("unable to generate prime number for RSA key");
    }

    protected boolean isProbablePrime(BigInteger bigInteger) {
        return !Primes.hasAnySmallFactors(bigInteger) && Primes.isMRProbablePrime(bigInteger, this.param.getRandom(), getNumberOfIterations(bigInteger.bitLength(), this.param.getCertainty()));
    }

    private static int getNumberOfIterations(int i, int i2) {
        if (i >= 1536) {
            if (i2 <= 100) {
                return 3;
            }
            if (i2 <= 128) {
                return 4;
            }
            return 4 + (((i2 - 128) + 1) / 2);
        } else if (i >= 1024) {
            if (i2 <= 100) {
                return 4;
            }
            if (i2 <= 112) {
                return 5;
            }
            return 5 + (((i2 - Opcode.IREM) + 1) / 2);
        } else if (i < 512) {
            if (i2 <= 80) {
                return 40;
            }
            return 40 + (((i2 - 80) + 1) / 2);
        } else if (i2 <= 80) {
            return 5;
        } else {
            if (i2 <= 100) {
                return 7;
            }
            return 7 + (((i2 - 100) + 1) / 2);
        }
    }
}