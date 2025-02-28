package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Properties;

/* loaded from: classes2.dex */
public class RSAKeyParameters extends AsymmetricKeyParameter {
    private BigInteger exponent;
    private BigInteger modulus;
    private static final BigIntegers.Cache validated = new BigIntegers.Cache();
    private static final BigInteger SMALL_PRIMES_PRODUCT = new BigInteger("8138e8a0fcf3a4e84a771d40fd305d7f4aa59306d7251de54d98af8fe95729a1f73d893fa424cd2edc8636a6c3285e022b0e3866a565ae8108eed8591cd4fe8d2ce86165a978d719ebf647f362d33fca29cd179fb42401cbaf3df0c614056f9c8f3cfd51e474afb6bc6974f78db8aba8e9e517fded658591ab7502bd41849462f", 16);

    public RSAKeyParameters(boolean z, BigInteger bigInteger, BigInteger bigInteger2) {
        this(z, bigInteger, bigInteger2, false);
    }

    public RSAKeyParameters(boolean z, BigInteger bigInteger, BigInteger bigInteger2, boolean z2) {
        super(z);
        if (!z && (bigInteger2.intValue() & 1) == 0) {
            throw new IllegalArgumentException("RSA publicExponent is even");
        }
        this.modulus = validated.contains(bigInteger) ? bigInteger : validate(bigInteger, z2);
        this.exponent = bigInteger2;
    }

    private static int getMRIterations(int i) {
        if (i >= 1536) {
            return 3;
        }
        if (i >= 1024) {
            return 4;
        }
        return i >= 512 ? 7 : 50;
    }

    private static boolean hasAnySmallFactors(BigInteger bigInteger) {
        BigInteger bigInteger2 = SMALL_PRIMES_PRODUCT;
        if (bigInteger.bitLength() < bigInteger2.bitLength()) {
            bigInteger2 = bigInteger;
            bigInteger = bigInteger2;
        }
        return !BigIntegers.modOddIsCoprimeVar(bigInteger, bigInteger2);
    }

    private static BigInteger validate(BigInteger bigInteger, boolean z) {
        if (!z) {
            if ((bigInteger.intValue() & 1) == 0) {
                throw new IllegalArgumentException("RSA modulus is even");
            }
            if (Properties.isOverrideSet("org.bouncycastle.rsa.allow_unsafe_mod")) {
                return bigInteger;
            }
            if (Properties.asInteger("org.bouncycastle.rsa.max_size", 16384) < bigInteger.bitLength()) {
                throw new IllegalArgumentException("RSA modulus out of range");
            }
            if (hasAnySmallFactors(bigInteger)) {
                throw new IllegalArgumentException("RSA modulus has a small prime factor");
            }
            int asInteger = Properties.asInteger("org.bouncycastle.rsa.max_mr_tests", getMRIterations(bigInteger.bitLength() / 2));
            if (asInteger > 0 && !Primes.enhancedMRProbablePrimeTest(bigInteger, CryptoServicesRegistrar.getSecureRandom(), asInteger).isProvablyComposite()) {
                throw new IllegalArgumentException("RSA modulus is not composite");
            }
        }
        validated.add(bigInteger);
        return bigInteger;
    }

    public BigInteger getExponent() {
        return this.exponent;
    }

    public BigInteger getModulus() {
        return this.modulus;
    }
}