package org.bouncycastle.crypto.generators;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Vector;
import javassist.bytecode.Opcode;
import javassist.compiler.TokenId;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyParameters;
import org.bouncycastle.crypto.params.NaccacheSternPrivateKeyParameters;
import org.bouncycastle.math.Primes;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/NaccacheSternKeyPairGenerator.class */
public class NaccacheSternKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private NaccacheSternKeyGenerationParameters param;
    private static int[] smallPrimes = {3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, Opcode.LSUB, Opcode.DSUB, Opcode.DMUL, Opcode.LDIV, Opcode.LREM, Opcode.LAND, Opcode.LXOR, Opcode.L2F, Opcode.F2I, Opcode.FCMPL, Opcode.DCMPL, Opcode.IFGT, Opcode.IF_ICMPGT, Opcode.GOTO, Opcode.LRETURN, Opcode.PUTSTATIC, Opcode.PUTFIELD, Opcode.ATHROW, Opcode.INSTANCEOF, Opcode.MULTIANEWARRAY, Opcode.IFNONNULL, Primes.SMALL_FACTOR_LIMIT, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, TokenId.CLASS, TokenId.f2DO, TokenId.ELSE, TokenId.FLOAT, TokenId.PROTECTED, TokenId.SWITCH, TokenId.STRICT, 349, TokenId.MUL_E, TokenId.f6GE, TokenId.RSHIFT_E, 373, 379, 383, 389, 397, TokenId.CharConstant, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557};
    private static final BigInteger ONE = BigInteger.valueOf(1);

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.param = (NaccacheSternKeyGenerationParameters) keyGenerationParameters;
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger generatePrime;
        BigInteger add;
        BigInteger generatePrime2;
        BigInteger add2;
        BigInteger bigInteger;
        BigInteger createRandomPrime;
        int strength = this.param.getStrength();
        SecureRandom random = this.param.getRandom();
        int certainty = this.param.getCertainty();
        boolean isDebug = this.param.isDebug();
        if (isDebug) {
            System.out.println("Fetching first " + this.param.getCntSmallPrimes() + " primes.");
        }
        Vector permuteList = permuteList(findFirstPrimes(this.param.getCntSmallPrimes()), random);
        BigInteger bigInteger2 = ONE;
        BigInteger bigInteger3 = ONE;
        for (int i = 0; i < permuteList.size() / 2; i++) {
            bigInteger2 = bigInteger2.multiply((BigInteger) permuteList.elementAt(i));
        }
        for (int size = permuteList.size() / 2; size < permuteList.size(); size++) {
            bigInteger3 = bigInteger3.multiply((BigInteger) permuteList.elementAt(size));
        }
        BigInteger multiply = bigInteger2.multiply(bigInteger3);
        int bitLength = (strength - multiply.bitLength()) - 48;
        BigInteger generatePrime3 = generatePrime((bitLength / 2) + 1, certainty, random);
        BigInteger generatePrime4 = generatePrime((bitLength / 2) + 1, certainty, random);
        long j = 0;
        if (isDebug) {
            System.out.println("generating p and q");
        }
        BigInteger shiftLeft = generatePrime3.multiply(bigInteger2).shiftLeft(1);
        BigInteger shiftLeft2 = generatePrime4.multiply(bigInteger3).shiftLeft(1);
        while (true) {
            j++;
            generatePrime = generatePrime(24, certainty, random);
            add = generatePrime.multiply(shiftLeft).add(ONE);
            if (add.isProbablePrime(certainty)) {
                while (true) {
                    generatePrime2 = generatePrime(24, certainty, random);
                    if (!generatePrime.equals(generatePrime2)) {
                        add2 = generatePrime2.multiply(shiftLeft2).add(ONE);
                        if (add2.isProbablePrime(certainty)) {
                            break;
                        }
                    }
                }
                if (!multiply.gcd(generatePrime.multiply(generatePrime2)).equals(ONE)) {
                    continue;
                } else if (add.multiply(add2).bitLength() >= strength) {
                    break;
                } else if (isDebug) {
                    System.out.println("key size too small. Should be " + strength + " but is actually " + add.multiply(add2).bitLength());
                }
            }
        }
        if (isDebug) {
            System.out.println("needed " + j + " tries to generate p and q.");
        }
        BigInteger multiply2 = add.multiply(add2);
        BigInteger multiply3 = add.subtract(ONE).multiply(add2.subtract(ONE));
        long j2 = 0;
        if (isDebug) {
            System.out.println("generating g");
        }
        while (true) {
            Vector vector = new Vector();
            for (int i2 = 0; i2 != permuteList.size(); i2++) {
                BigInteger divide = multiply3.divide((BigInteger) permuteList.elementAt(i2));
                do {
                    j2++;
                    createRandomPrime = BigIntegers.createRandomPrime(strength, certainty, random);
                } while (createRandomPrime.modPow(divide, multiply2).equals(ONE));
                vector.addElement(createRandomPrime);
            }
            bigInteger = ONE;
            for (int i3 = 0; i3 < permuteList.size(); i3++) {
                bigInteger = bigInteger.multiply(((BigInteger) vector.elementAt(i3)).modPow(multiply.divide((BigInteger) permuteList.elementAt(i3)), multiply2)).mod(multiply2);
            }
            boolean z = false;
            int i4 = 0;
            while (true) {
                if (i4 >= permuteList.size()) {
                    break;
                } else if (bigInteger.modPow(multiply3.divide((BigInteger) permuteList.elementAt(i4)), multiply2).equals(ONE)) {
                    if (isDebug) {
                        System.out.println("g has order phi(n)/" + permuteList.elementAt(i4) + "\n g: " + bigInteger);
                    }
                    z = true;
                } else {
                    i4++;
                }
            }
            if (!z) {
                if (!bigInteger.modPow(multiply3.divide(BigInteger.valueOf(4L)), multiply2).equals(ONE)) {
                    if (!bigInteger.modPow(multiply3.divide(generatePrime), multiply2).equals(ONE)) {
                        if (!bigInteger.modPow(multiply3.divide(generatePrime2), multiply2).equals(ONE)) {
                            if (!bigInteger.modPow(multiply3.divide(generatePrime3), multiply2).equals(ONE)) {
                                if (!bigInteger.modPow(multiply3.divide(generatePrime4), multiply2).equals(ONE)) {
                                    break;
                                } else if (isDebug) {
                                    System.out.println("g has order phi(n)/b\n g: " + bigInteger);
                                }
                            } else if (isDebug) {
                                System.out.println("g has order phi(n)/a\n g: " + bigInteger);
                            }
                        } else if (isDebug) {
                            System.out.println("g has order phi(n)/q'\n g: " + bigInteger);
                        }
                    } else if (isDebug) {
                        System.out.println("g has order phi(n)/p'\n g: " + bigInteger);
                    }
                } else if (isDebug) {
                    System.out.println("g has order phi(n)/4\n g:" + bigInteger);
                }
            }
        }
        if (isDebug) {
            System.out.println("needed " + j2 + " tries to generate g");
            System.out.println();
            System.out.println("found new NaccacheStern cipher variables:");
            System.out.println("smallPrimes: " + permuteList);
            System.out.println("sigma:...... " + multiply + " (" + multiply.bitLength() + " bits)");
            System.out.println("a:.......... " + generatePrime3);
            System.out.println("b:.......... " + generatePrime4);
            System.out.println("p':......... " + generatePrime);
            System.out.println("q':......... " + generatePrime2);
            System.out.println("p:.......... " + add);
            System.out.println("q:.......... " + add2);
            System.out.println("n:.......... " + multiply2);
            System.out.println("phi(n):..... " + multiply3);
            System.out.println("g:.......... " + bigInteger);
            System.out.println();
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new NaccacheSternKeyParameters(false, bigInteger, multiply2, multiply.bitLength()), (AsymmetricKeyParameter) new NaccacheSternPrivateKeyParameters(bigInteger, multiply2, multiply.bitLength(), permuteList, multiply3));
    }

    private static BigInteger generatePrime(int i, int i2, SecureRandom secureRandom) {
        BigInteger createRandomPrime = BigIntegers.createRandomPrime(i, i2, secureRandom);
        while (true) {
            BigInteger bigInteger = createRandomPrime;
            if (bigInteger.bitLength() == i) {
                return bigInteger;
            }
            createRandomPrime = BigIntegers.createRandomPrime(i, i2, secureRandom);
        }
    }

    private static Vector permuteList(Vector vector, SecureRandom secureRandom) {
        Vector vector2 = new Vector();
        Vector vector3 = new Vector();
        for (int i = 0; i < vector.size(); i++) {
            vector3.addElement(vector.elementAt(i));
        }
        vector2.addElement(vector3.elementAt(0));
        vector3.removeElementAt(0);
        while (vector3.size() != 0) {
            vector2.insertElementAt(vector3.elementAt(0), getInt(secureRandom, vector2.size() + 1));
            vector3.removeElementAt(0);
        }
        return vector2;
    }

    private static int getInt(SecureRandom secureRandom, int i) {
        int nextInt;
        int i2;
        if ((i & (-i)) == i) {
            return (int) ((i * (secureRandom.nextInt() & Integer.MAX_VALUE)) >> 31);
        }
        do {
            nextInt = secureRandom.nextInt() & Integer.MAX_VALUE;
            i2 = nextInt % i;
        } while ((nextInt - i2) + (i - 1) < 0);
        return i2;
    }

    private static Vector findFirstPrimes(int i) {
        Vector vector = new Vector(i);
        for (int i2 = 0; i2 != i; i2++) {
            vector.addElement(BigInteger.valueOf(smallPrimes[i2]));
        }
        return vector;
    }
}