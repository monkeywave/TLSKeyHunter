package org.bouncycastle.crypto.generators;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.math.Primes;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public class NaccacheSternKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private NaccacheSternKeyGenerationParameters param;
    private static int[] smallPrimes = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, TypedValues.TYPE_TARGET, CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256, CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, 109, 113, 127, 131, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA, CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA, CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA, CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA, CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384, CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384, CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256, CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256, CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256, CipherSuite.TLS_SM4_CCM_SM3, Primes.SMALL_FACTOR_LIMIT, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, TypedValues.AttributesType.TYPE_EASING, 331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, TypedValues.CycleType.TYPE_CURVE_FIT, 409, 419, TypedValues.CycleType.TYPE_WAVE_SHAPE, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, TypedValues.PositionType.TYPE_PERCENT_WIDTH, 509, 521, 523, 541, 547, 557};
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private static Vector findFirstPrimes(int i) {
        Vector vector = new Vector(i);
        for (int i2 = 0; i2 != i; i2++) {
            vector.addElement(BigInteger.valueOf(smallPrimes[i2]));
        }
        return vector;
    }

    private static BigInteger generatePrime(int i, int i2, SecureRandom secureRandom) {
        BigInteger createRandomPrime;
        do {
            createRandomPrime = BigIntegers.createRandomPrime(i, i2, secureRandom);
        } while (createRandomPrime.bitLength() != i);
        return createRandomPrime;
    }

    private static int getInt(SecureRandom secureRandom, int i) {
        int nextInt;
        int i2;
        if (((-i) & i) == i) {
            return (int) ((i * (secureRandom.nextInt() & Integer.MAX_VALUE)) >> 31);
        }
        do {
            nextInt = secureRandom.nextInt() & Integer.MAX_VALUE;
            i2 = nextInt % i;
        } while ((nextInt - i2) + (i - 1) < 0);
        return i2;
    }

    private static Vector permuteList(Vector vector, SecureRandom secureRandom) {
        Vector vector2 = new Vector();
        Vector vector3 = new Vector();
        for (int i = 0; i < vector.size(); i++) {
            vector3.addElement(vector.elementAt(i));
        }
        vector2.addElement(vector3.elementAt(0));
        while (true) {
            vector3.removeElementAt(0);
            if (vector3.size() == 0) {
                return vector2;
            }
            vector2.insertElementAt(vector3.elementAt(0), getInt(secureRandom, vector2.size() + 1));
        }
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        long j;
        BigInteger generatePrime;
        BigInteger add;
        BigInteger generatePrime2;
        BigInteger bigInteger;
        BigInteger bigInteger2;
        BigInteger add2;
        BigInteger bigInteger3;
        BigInteger multiply;
        BigInteger bigInteger4;
        BigInteger bigInteger5;
        BigInteger bigInteger6;
        BigInteger bigInteger7;
        BigInteger bigInteger8;
        BigInteger bigInteger9;
        BigInteger bigInteger10;
        int i;
        BigInteger bigInteger11;
        BigInteger bigInteger12;
        BigInteger bigInteger13;
        PrintStream printStream;
        StringBuilder sb;
        long j2;
        BigInteger createRandomPrime;
        SecureRandom secureRandom;
        SecureRandom secureRandom2;
        int i2;
        BigInteger bigInteger14;
        BigInteger bigInteger15;
        int i3;
        int strength = this.param.getStrength();
        SecureRandom random = this.param.getRandom();
        int certainty = this.param.getCertainty();
        boolean isDebug = this.param.isDebug();
        if (isDebug) {
            System.out.println("Fetching first " + this.param.getCntSmallPrimes() + " primes.");
        }
        Vector permuteList = permuteList(findFirstPrimes(this.param.getCntSmallPrimes()), random);
        BigInteger bigInteger16 = ONE;
        BigInteger bigInteger17 = bigInteger16;
        for (int i4 = 0; i4 < permuteList.size() / 2; i4++) {
            bigInteger17 = bigInteger17.multiply((BigInteger) permuteList.elementAt(i4));
        }
        for (int size = permuteList.size() / 2; size < permuteList.size(); size++) {
            bigInteger16 = bigInteger16.multiply((BigInteger) permuteList.elementAt(size));
        }
        BigInteger multiply2 = bigInteger17.multiply(bigInteger16);
        int bitLength = (((strength - multiply2.bitLength()) - 48) / 2) + 1;
        BigInteger generatePrime3 = generatePrime(bitLength, certainty, random);
        BigInteger generatePrime4 = generatePrime(bitLength, certainty, random);
        if (isDebug) {
            System.out.println("generating p and q");
        }
        BigInteger shiftLeft = generatePrime3.multiply(bigInteger17).shiftLeft(1);
        BigInteger shiftLeft2 = generatePrime4.multiply(bigInteger16).shiftLeft(1);
        long j3 = 0;
        while (true) {
            j = j3 + 1;
            generatePrime = generatePrime(24, certainty, random);
            add = generatePrime.multiply(shiftLeft).add(ONE);
            if (add.isProbablePrime(certainty)) {
                while (true) {
                    do {
                        generatePrime2 = generatePrime(24, certainty, random);
                    } while (generatePrime.equals(generatePrime2));
                    BigInteger multiply3 = generatePrime2.multiply(shiftLeft2);
                    bigInteger = shiftLeft2;
                    bigInteger2 = ONE;
                    add2 = multiply3.add(bigInteger2);
                    if (add2.isProbablePrime(certainty)) {
                        break;
                    }
                    shiftLeft2 = bigInteger;
                    shiftLeft = shiftLeft;
                }
                bigInteger3 = shiftLeft;
                if (BigIntegers.modOddIsCoprime(generatePrime.multiply(generatePrime2), multiply2)) {
                    multiply = add.multiply(add2);
                    bigInteger4 = generatePrime4;
                    if (multiply.bitLength() >= strength) {
                        break;
                    }
                    int i5 = strength;
                    secureRandom2 = random;
                    i2 = certainty;
                    bigInteger14 = generatePrime3;
                    bigInteger15 = bigInteger4;
                    if (isDebug) {
                        i3 = i5;
                        System.out.println("key size too small. Should be " + i3 + " but is actually " + add.multiply(add2).bitLength());
                    } else {
                        i3 = i5;
                    }
                } else {
                    i3 = strength;
                    secureRandom2 = random;
                    i2 = certainty;
                    bigInteger15 = generatePrime4;
                    bigInteger14 = generatePrime3;
                }
            } else {
                secureRandom2 = random;
                i2 = certainty;
                bigInteger = shiftLeft2;
                bigInteger3 = shiftLeft;
                bigInteger14 = generatePrime3;
                i3 = strength;
                bigInteger15 = generatePrime4;
            }
            generatePrime4 = bigInteger15;
            strength = i3;
            generatePrime3 = bigInteger14;
            j3 = j;
            shiftLeft2 = bigInteger;
            shiftLeft = bigInteger3;
            random = secureRandom2;
            certainty = i2;
        }
        if (isDebug) {
            bigInteger6 = generatePrime3;
            bigInteger5 = generatePrime2;
            System.out.println("needed " + j + " tries to generate p and q.");
        } else {
            bigInteger5 = generatePrime2;
            bigInteger6 = generatePrime3;
        }
        BigInteger multiply4 = add.subtract(bigInteger2).multiply(add2.subtract(bigInteger2));
        if (isDebug) {
            System.out.println("generating g");
        }
        long j4 = 0;
        while (true) {
            Vector vector = new Vector();
            bigInteger7 = add2;
            int i6 = 0;
            while (i6 != permuteList.size()) {
                BigInteger divide = multiply4.divide((BigInteger) permuteList.elementAt(i6));
                while (true) {
                    j2 = j4 + 1;
                    createRandomPrime = BigIntegers.createRandomPrime(strength, certainty, random);
                    secureRandom = random;
                    if (createRandomPrime.modPow(divide, multiply).equals(ONE)) {
                        j4 = j2;
                        random = secureRandom;
                    }
                }
                vector.addElement(createRandomPrime);
                i6++;
                j4 = j2;
                random = secureRandom;
            }
            SecureRandom secureRandom3 = random;
            bigInteger8 = ONE;
            int i7 = 0;
            while (i7 < permuteList.size()) {
                bigInteger8 = bigInteger8.multiply(((BigInteger) vector.elementAt(i7)).modPow(multiply2.divide((BigInteger) permuteList.elementAt(i7)), multiply)).mod(multiply);
                i7++;
                certainty = certainty;
            }
            int i8 = certainty;
            int i9 = 0;
            while (true) {
                if (i9 >= permuteList.size()) {
                    BigInteger modPow = bigInteger8.modPow(multiply4.divide(BigInteger.valueOf(4L)), multiply);
                    BigInteger bigInteger18 = ONE;
                    if (!modPow.equals(bigInteger18)) {
                        if (!bigInteger8.modPow(multiply4.divide(generatePrime), multiply).equals(bigInteger18)) {
                            bigInteger9 = bigInteger5;
                            if (!bigInteger8.modPow(multiply4.divide(bigInteger9), multiply).equals(bigInteger18)) {
                                bigInteger10 = bigInteger6;
                                if (!bigInteger8.modPow(multiply4.divide(bigInteger10), multiply).equals(bigInteger18)) {
                                    i = strength;
                                    bigInteger11 = bigInteger4;
                                    if (!bigInteger8.modPow(multiply4.divide(bigInteger11), multiply).equals(bigInteger18)) {
                                        break;
                                    } else if (isDebug) {
                                        bigInteger13 = multiply4;
                                        System.out.println("g has order phi(n)/b\n g: " + bigInteger8);
                                    } else {
                                        bigInteger13 = multiply4;
                                    }
                                } else {
                                    if (isDebug) {
                                        i = strength;
                                        System.out.println("g has order phi(n)/a\n g: " + bigInteger8);
                                    } else {
                                        i = strength;
                                    }
                                    bigInteger13 = multiply4;
                                }
                            } else {
                                if (isDebug) {
                                    System.out.println("g has order phi(n)/q'\n g: " + bigInteger8);
                                }
                                bigInteger13 = multiply4;
                                bigInteger10 = bigInteger6;
                            }
                        } else if (isDebug) {
                            printStream = System.out;
                            sb = new StringBuilder("g has order phi(n)/p'\n g: ");
                            printStream.println(sb.append(bigInteger8).toString());
                        }
                    } else if (isDebug) {
                        printStream = System.out;
                        sb = new StringBuilder("g has order phi(n)/4\n g:");
                        printStream.println(sb.append(bigInteger8).toString());
                    }
                } else if (!bigInteger8.modPow(multiply4.divide((BigInteger) permuteList.elementAt(i9)), multiply).equals(ONE)) {
                    i9++;
                } else if (isDebug) {
                    System.out.println("g has order phi(n)/" + permuteList.elementAt(i9) + "\n g: " + bigInteger8);
                }
            }
            bigInteger13 = multiply4;
            bigInteger10 = bigInteger6;
            bigInteger9 = bigInteger5;
            i = strength;
            bigInteger11 = bigInteger4;
            bigInteger4 = bigInteger11;
            bigInteger5 = bigInteger9;
            multiply4 = bigInteger13;
            strength = i;
            random = secureRandom3;
            certainty = i8;
            bigInteger6 = bigInteger10;
            add2 = bigInteger7;
        }
        BigInteger bigInteger19 = multiply4;
        if (isDebug) {
            System.out.println("needed " + j4 + " tries to generate g");
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + permuteList);
            System.out.println("sigma:...... " + multiply2 + " (" + multiply2.bitLength() + " bits)");
            System.out.println("a:.......... " + bigInteger10);
            System.out.println("b:.......... " + bigInteger11);
            System.out.println("p':......... " + generatePrime);
            System.out.println("q':......... " + bigInteger9);
            System.out.println("p:.......... " + add);
            System.out.println("q:.......... " + bigInteger7);
            System.out.println("n:.......... " + multiply);
            bigInteger12 = bigInteger19;
            System.out.println("phi(n):..... " + bigInteger12);
            System.out.println("g:.......... " + bigInteger8);
            System.out.println();
        } else {
            bigInteger12 = bigInteger19;
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new NaccacheSternKeyParameters(false, bigInteger8, multiply, multiply2.bitLength()), (AsymmetricKeyParameter) new NaccacheSternPrivateKeyParameters(bigInteger8, multiply, multiply2.bitLength(), permuteList, bigInteger12));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (NaccacheSternKeyGenerationParameters) keyGenerationParameters;
        CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("NaccacheStern KeyGen", ConstraintUtils.bitsOfSecurityForFF(keyGenerationParameters.getStrength()), keyGenerationParameters, CryptoServicePurpose.KEYGEN));
    }
}