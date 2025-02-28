package org.bouncycastle.math;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.math.BigInteger;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
public abstract class Primes {
    public static final int SMALL_FACTOR_LIMIT = 211;
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /* loaded from: classes2.dex */
    public static class MROutput {
        private BigInteger factor;
        private boolean provablyComposite;

        private MROutput(boolean z, BigInteger bigInteger) {
            this.provablyComposite = z;
            this.factor = bigInteger;
        }

        static /* synthetic */ MROutput access$000() {
            return probablyPrime();
        }

        static /* synthetic */ MROutput access$200() {
            return provablyCompositeNotPrimePower();
        }

        private static MROutput probablyPrime() {
            return new MROutput(false, null);
        }

        private static MROutput provablyCompositeNotPrimePower() {
            return new MROutput(true, null);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static MROutput provablyCompositeWithFactor(BigInteger bigInteger) {
            return new MROutput(true, bigInteger);
        }

        public BigInteger getFactor() {
            return this.factor;
        }

        public boolean isNotPrimePower() {
            return this.provablyComposite && this.factor == null;
        }

        public boolean isProvablyComposite() {
            return this.provablyComposite;
        }
    }

    /* loaded from: classes2.dex */
    public static class STOutput {
        private BigInteger prime;
        private int primeGenCounter;
        private byte[] primeSeed;

        private STOutput(BigInteger bigInteger, byte[] bArr, int i) {
            this.prime = bigInteger;
            this.primeSeed = bArr;
            this.primeGenCounter = i;
        }

        public BigInteger getPrime() {
            return this.prime;
        }

        public int getPrimeGenCounter() {
            return this.primeGenCounter;
        }

        public byte[] getPrimeSeed() {
            return this.primeSeed;
        }
    }

    private static void checkCandidate(BigInteger bigInteger, String str) {
        if (bigInteger == null || bigInteger.signum() < 1 || bigInteger.bitLength() < 2) {
            throw new IllegalArgumentException("'" + str + "' must be non-null and >= 2");
        }
    }

    public static MROutput enhancedMRProbablePrimeTest(BigInteger bigInteger, SecureRandom secureRandom, int i) {
        boolean z;
        BigInteger bigInteger2;
        checkCandidate(bigInteger, "candidate");
        if (secureRandom != null) {
            if (i >= 1) {
                if (bigInteger.bitLength() == 2) {
                    return MROutput.access$000();
                }
                if (bigInteger.testBit(0)) {
                    BigInteger subtract = bigInteger.subtract(ONE);
                    BigInteger subtract2 = bigInteger.subtract(TWO);
                    int lowestSetBit = subtract.getLowestSetBit();
                    BigInteger shiftRight = subtract.shiftRight(lowestSetBit);
                    for (int i2 = 0; i2 < i; i2++) {
                        BigInteger createRandomInRange = BigIntegers.createRandomInRange(TWO, subtract2, secureRandom);
                        BigInteger gcd = createRandomInRange.gcd(bigInteger);
                        BigInteger bigInteger3 = ONE;
                        if (gcd.compareTo(bigInteger3) > 0) {
                            return MROutput.provablyCompositeWithFactor(gcd);
                        }
                        BigInteger modPow = createRandomInRange.modPow(shiftRight, bigInteger);
                        if (!modPow.equals(bigInteger3) && !modPow.equals(subtract)) {
                            int i3 = 1;
                            while (true) {
                                if (i3 >= lowestSetBit) {
                                    z = false;
                                    bigInteger2 = modPow;
                                    break;
                                }
                                bigInteger2 = modPow.modPow(TWO, bigInteger);
                                if (bigInteger2.equals(subtract)) {
                                    z = true;
                                    break;
                                } else if (bigInteger2.equals(ONE)) {
                                    z = false;
                                    break;
                                } else {
                                    i3++;
                                    modPow = bigInteger2;
                                }
                            }
                            if (!z) {
                                BigInteger bigInteger4 = ONE;
                                if (!bigInteger2.equals(bigInteger4)) {
                                    modPow = bigInteger2.modPow(TWO, bigInteger);
                                    if (modPow.equals(bigInteger4)) {
                                        modPow = bigInteger2;
                                    }
                                }
                                BigInteger gcd2 = modPow.subtract(bigInteger4).gcd(bigInteger);
                                return gcd2.compareTo(bigInteger4) > 0 ? MROutput.provablyCompositeWithFactor(gcd2) : MROutput.access$200();
                            }
                        }
                    }
                    return MROutput.access$000();
                }
                return MROutput.provablyCompositeWithFactor(TWO);
            }
            throw new IllegalArgumentException("'iterations' must be > 0");
        }
        throw new IllegalArgumentException("'random' cannot be null");
    }

    private static int extract32(byte[] bArr) {
        int min = Math.min(4, bArr.length);
        int i = 0;
        int i2 = 0;
        while (i < min) {
            int i3 = i + 1;
            i2 |= (bArr[bArr.length - i3] & UByte.MAX_VALUE) << (i * 8);
            i = i3;
        }
        return i2;
    }

    public static STOutput generateSTRandomPrime(Digest digest, int i, byte[] bArr) {
        if (digest != null) {
            if (i >= 2) {
                if (bArr == null || bArr.length == 0) {
                    throw new IllegalArgumentException("'inputSeed' cannot be null or empty");
                }
                return implSTRandomPrime(digest, i, Arrays.clone(bArr));
            }
            throw new IllegalArgumentException("'length' must be >= 2");
        }
        throw new IllegalArgumentException("'hash' cannot be null");
    }

    public static boolean hasAnySmallFactors(BigInteger bigInteger) {
        checkCandidate(bigInteger, "candidate");
        return implHasAnySmallFactors(bigInteger);
    }

    private static void hash(Digest digest, byte[] bArr, byte[] bArr2, int i) {
        digest.update(bArr, 0, bArr.length);
        digest.doFinal(bArr2, i);
    }

    private static BigInteger hashGen(Digest digest, byte[] bArr, int i) {
        int digestSize = digest.getDigestSize();
        int i2 = i * digestSize;
        byte[] bArr2 = new byte[i2];
        for (int i3 = 0; i3 < i; i3++) {
            i2 -= digestSize;
            hash(digest, bArr, bArr2, i2);
            inc(bArr, 1);
        }
        return new BigInteger(1, bArr2);
    }

    private static boolean implHasAnySmallFactors(BigInteger bigInteger) {
        int intValue = bigInteger.mod(BigInteger.valueOf(223092870)).intValue();
        if (intValue % 2 != 0 && intValue % 3 != 0 && intValue % 5 != 0 && intValue % 7 != 0 && intValue % 11 != 0 && intValue % 13 != 0 && intValue % 17 != 0 && intValue % 19 != 0 && intValue % 23 != 0) {
            int intValue2 = bigInteger.mod(BigInteger.valueOf(58642669)).intValue();
            if (intValue2 % 29 != 0 && intValue2 % 31 != 0 && intValue2 % 37 != 0 && intValue2 % 41 != 0 && intValue2 % 43 != 0) {
                int intValue3 = bigInteger.mod(BigInteger.valueOf(600662303)).intValue();
                if (intValue3 % 47 != 0 && intValue3 % 53 != 0 && intValue3 % 59 != 0 && intValue3 % 61 != 0 && intValue3 % 67 != 0) {
                    int intValue4 = bigInteger.mod(BigInteger.valueOf(33984931)).intValue();
                    if (intValue4 % 71 != 0 && intValue4 % 73 != 0 && intValue4 % 79 != 0 && intValue4 % 83 != 0) {
                        int intValue5 = bigInteger.mod(BigInteger.valueOf(89809099)).intValue();
                        if (intValue5 % 89 != 0 && intValue5 % 97 != 0 && intValue5 % TypedValues.TYPE_TARGET != 0 && intValue5 % CipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 != 0) {
                            int intValue6 = bigInteger.mod(BigInteger.valueOf(167375713)).intValue();
                            if (intValue6 % CipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 != 0 && intValue6 % 109 != 0 && intValue6 % 113 != 0 && intValue6 % 127 != 0) {
                                int intValue7 = bigInteger.mod(BigInteger.valueOf(371700317)).intValue();
                                if (intValue7 % 131 != 0 && intValue7 % CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA != 0 && intValue7 % CipherSuite.TLS_PSK_WITH_3DES_EDE_CBC_SHA != 0 && intValue7 % CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA != 0) {
                                    int intValue8 = bigInteger.mod(BigInteger.valueOf(645328247)).intValue();
                                    if (intValue8 % CipherSuite.TLS_DH_DSS_WITH_SEED_CBC_SHA != 0 && intValue8 % CipherSuite.TLS_RSA_WITH_AES_256_GCM_SHA384 != 0 && intValue8 % CipherSuite.TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 != 0 && intValue8 % CipherSuite.TLS_DH_anon_WITH_AES_256_GCM_SHA384 != 0) {
                                        int intValue9 = bigInteger.mod(BigInteger.valueOf(1070560157)).intValue();
                                        if (intValue9 % CipherSuite.TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 != 0 && intValue9 % CipherSuite.TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 != 0 && intValue9 % CipherSuite.TLS_DHE_PSK_WITH_NULL_SHA384 != 0 && intValue9 % CipherSuite.TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256 != 0) {
                                            int intValue10 = bigInteger.mod(BigInteger.valueOf(1596463769)).intValue();
                                            if (intValue10 % CipherSuite.TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256 != 0 && intValue10 % CipherSuite.TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256 != 0 && intValue10 % CipherSuite.TLS_SM4_CCM_SM3 != 0 && intValue10 % SMALL_FACTOR_LIMIT != 0) {
                                                return false;
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

    private static boolean implMRProbablePrimeToBase(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, int i, BigInteger bigInteger4) {
        BigInteger modPow = bigInteger4.modPow(bigInteger3, bigInteger);
        if (modPow.equals(ONE) || modPow.equals(bigInteger2)) {
            return true;
        }
        for (int i2 = 1; i2 < i; i2++) {
            modPow = modPow.modPow(TWO, bigInteger);
            if (modPow.equals(bigInteger2)) {
                return true;
            }
            if (modPow.equals(ONE)) {
                return false;
            }
        }
        return false;
    }

    private static STOutput implSTRandomPrime(Digest digest, int i, byte[] bArr) {
        Object obj;
        int digestSize = digest.getDigestSize();
        Object obj2 = null;
        int i2 = 1;
        if (i < 33) {
            byte[] bArr2 = new byte[digestSize];
            byte[] bArr3 = new byte[digestSize];
            int i3 = 0;
            do {
                hash(digest, bArr, bArr2, 0);
                inc(bArr, 1);
                hash(digest, bArr, bArr3, 0);
                inc(bArr, 1);
                i3++;
                long extract32 = (((extract32(bArr2) ^ extract32(bArr3)) & ((-1) >>> (32 - i))) | (1 << (i - 1)) | 1) & BodyPartID.bodyIdMax;
                if (isPrime32(extract32)) {
                    return new STOutput(BigInteger.valueOf(extract32), bArr, i3);
                }
            } while (i3 <= i * 4);
            throw new IllegalStateException("Too many iterations in Shawe-Taylor Random_Prime Routine");
        }
        STOutput implSTRandomPrime = implSTRandomPrime(digest, (i + 3) / 2, bArr);
        BigInteger prime = implSTRandomPrime.getPrime();
        byte[] primeSeed = implSTRandomPrime.getPrimeSeed();
        int primeGenCounter = implSTRandomPrime.getPrimeGenCounter();
        int i4 = i - 1;
        int i5 = (i4 / (digestSize * 8)) + 1;
        BigInteger hashGen = hashGen(digest, primeSeed, i5);
        BigInteger bigInteger = ONE;
        BigInteger bit = hashGen.mod(bigInteger.shiftLeft(i4)).setBit(i4);
        BigInteger shiftLeft = prime.shiftLeft(1);
        BigInteger shiftLeft2 = bit.subtract(bigInteger).divide(shiftLeft).add(bigInteger).shiftLeft(1);
        BigInteger add = shiftLeft2.multiply(prime).add(bigInteger);
        int i6 = primeGenCounter;
        int i7 = 0;
        while (true) {
            if (add.bitLength() > i) {
                BigInteger bigInteger2 = ONE;
                shiftLeft2 = bigInteger2.shiftLeft(i4).subtract(bigInteger2).divide(shiftLeft).add(bigInteger2).shiftLeft(i2);
                add = shiftLeft2.multiply(prime).add(bigInteger2);
            }
            i6 += i2;
            if (implHasAnySmallFactors(add)) {
                obj = obj2;
                inc(primeSeed, i5);
            } else {
                BigInteger add2 = hashGen(digest, primeSeed, i5).mod(add.subtract(THREE)).add(TWO);
                BigInteger add3 = shiftLeft2.add(BigInteger.valueOf(i7));
                BigInteger modPow = add2.modPow(add3, add);
                BigInteger bigInteger3 = ONE;
                if (add.gcd(modPow.subtract(bigInteger3)).equals(bigInteger3) && modPow.modPow(prime, add).equals(bigInteger3)) {
                    return new STOutput(add, primeSeed, i6);
                }
                obj = null;
                shiftLeft2 = add3;
                i7 = 0;
            }
            if (i6 >= (i * 4) + primeGenCounter) {
                throw new IllegalStateException("Too many iterations in Shawe-Taylor Random_Prime Routine");
            }
            i7 += 2;
            add = add.add(shiftLeft);
            obj2 = obj;
            i2 = 1;
        }
    }

    private static void inc(byte[] bArr, int i) {
        int length = bArr.length;
        while (i > 0) {
            length--;
            if (length < 0) {
                return;
            }
            int i2 = i + (bArr[length] & 255);
            bArr[length] = (byte) i2;
            i = i2 >>> 8;
        }
    }

    public static boolean isMRProbablePrime(BigInteger bigInteger, SecureRandom secureRandom, int i) {
        checkCandidate(bigInteger, "candidate");
        if (secureRandom != null) {
            if (i >= 1) {
                if (bigInteger.bitLength() == 2) {
                    return true;
                }
                if (bigInteger.testBit(0)) {
                    BigInteger subtract = bigInteger.subtract(ONE);
                    BigInteger subtract2 = bigInteger.subtract(TWO);
                    int lowestSetBit = subtract.getLowestSetBit();
                    BigInteger shiftRight = subtract.shiftRight(lowestSetBit);
                    for (int i2 = 0; i2 < i; i2++) {
                        if (!implMRProbablePrimeToBase(bigInteger, subtract, shiftRight, lowestSetBit, BigIntegers.createRandomInRange(TWO, subtract2, secureRandom))) {
                            return false;
                        }
                    }
                    return true;
                }
                return false;
            }
            throw new IllegalArgumentException("'iterations' must be > 0");
        }
        throw new IllegalArgumentException("'random' cannot be null");
    }

    public static boolean isMRProbablePrimeToBase(BigInteger bigInteger, BigInteger bigInteger2) {
        checkCandidate(bigInteger, "candidate");
        checkCandidate(bigInteger2, "base");
        BigInteger bigInteger3 = ONE;
        if (bigInteger2.compareTo(bigInteger.subtract(bigInteger3)) < 0) {
            if (bigInteger.bitLength() == 2) {
                return true;
            }
            BigInteger subtract = bigInteger.subtract(bigInteger3);
            int lowestSetBit = subtract.getLowestSetBit();
            return implMRProbablePrimeToBase(bigInteger, subtract, subtract.shiftRight(lowestSetBit), lowestSetBit, bigInteger2);
        }
        throw new IllegalArgumentException("'base' must be < ('candidate' - 1)");
    }

    private static boolean isPrime32(long j) {
        if ((j >>> 32) != 0) {
            throw new IllegalArgumentException("Size limit exceeded");
        }
        int i = (j > 5L ? 1 : (j == 5L ? 0 : -1));
        if (i <= 0) {
            return j == 2 || j == 3 || i == 0;
        } else if ((1 & j) == 0 || j % 3 == 0 || j % 5 == 0) {
            return false;
        } else {
            long[] jArr = {1, 7, 11, 13, 17, 19, 23, 29};
            long j2 = 0;
            int i2 = 1;
            while (true) {
                if (i2 >= 8) {
                    j2 += 30;
                    if (j2 * j2 >= j) {
                        return true;
                    }
                    i2 = 0;
                } else if (j % (jArr[i2] + j2) == 0) {
                    return j < 30;
                } else {
                    i2++;
                }
            }
        }
    }
}