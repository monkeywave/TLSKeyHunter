package org.bouncycastle.math;

import java.math.BigInteger;
import java.security.SecureRandom;
import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/Primes.class */
public abstract class Primes {
    public static final int SMALL_FACTOR_LIMIT = 211;
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/Primes$MROutput.class */
    public static class MROutput {
        private boolean provablyComposite;
        private BigInteger factor;

        private static MROutput probablyPrime() {
            return new MROutput(false, null);
        }

        /* JADX INFO: Access modifiers changed from: private */
        public static MROutput provablyCompositeWithFactor(BigInteger bigInteger) {
            return new MROutput(true, bigInteger);
        }

        private static MROutput provablyCompositeNotPrimePower() {
            return new MROutput(true, null);
        }

        private MROutput(boolean z, BigInteger bigInteger) {
            this.provablyComposite = z;
            this.factor = bigInteger;
        }

        public BigInteger getFactor() {
            return this.factor;
        }

        public boolean isProvablyComposite() {
            return this.provablyComposite;
        }

        public boolean isNotPrimePower() {
            return this.provablyComposite && this.factor == null;
        }

        static /* synthetic */ MROutput access$000() {
            return probablyPrime();
        }

        static /* synthetic */ MROutput access$200() {
            return provablyCompositeNotPrimePower();
        }
    }

    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/Primes$STOutput.class */
    public static class STOutput {
        private BigInteger prime;
        private byte[] primeSeed;
        private int primeGenCounter;

        private STOutput(BigInteger bigInteger, byte[] bArr, int i) {
            this.prime = bigInteger;
            this.primeSeed = bArr;
            this.primeGenCounter = i;
        }

        public BigInteger getPrime() {
            return this.prime;
        }

        public byte[] getPrimeSeed() {
            return this.primeSeed;
        }

        public int getPrimeGenCounter() {
            return this.primeGenCounter;
        }
    }

    public static STOutput generateSTRandomPrime(Digest digest, int i, byte[] bArr) {
        if (digest == null) {
            throw new IllegalArgumentException("'hash' cannot be null");
        }
        if (i < 2) {
            throw new IllegalArgumentException("'length' must be >= 2");
        }
        if (bArr == null || bArr.length == 0) {
            throw new IllegalArgumentException("'inputSeed' cannot be null or empty");
        }
        return implSTRandomPrime(digest, i, Arrays.clone(bArr));
    }

    public static MROutput enhancedMRProbablePrimeTest(BigInteger bigInteger, SecureRandom secureRandom, int i) {
        checkCandidate(bigInteger, "candidate");
        if (secureRandom == null) {
            throw new IllegalArgumentException("'random' cannot be null");
        }
        if (i < 1) {
            throw new IllegalArgumentException("'iterations' must be > 0");
        }
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
                if (gcd.compareTo(ONE) > 0) {
                    return MROutput.provablyCompositeWithFactor(gcd);
                }
                BigInteger modPow = createRandomInRange.modPow(shiftRight, bigInteger);
                if (!modPow.equals(ONE) && !modPow.equals(subtract)) {
                    boolean z = false;
                    BigInteger bigInteger2 = modPow;
                    int i3 = 1;
                    while (true) {
                        if (i3 >= lowestSetBit) {
                            break;
                        }
                        modPow = modPow.modPow(TWO, bigInteger);
                        if (modPow.equals(subtract)) {
                            z = true;
                            break;
                        } else if (modPow.equals(ONE)) {
                            break;
                        } else {
                            bigInteger2 = modPow;
                            i3++;
                        }
                    }
                    if (!z) {
                        if (!modPow.equals(ONE)) {
                            bigInteger2 = modPow;
                            BigInteger modPow2 = modPow.modPow(TWO, bigInteger);
                            if (!modPow2.equals(ONE)) {
                                bigInteger2 = modPow2;
                            }
                        }
                        BigInteger gcd2 = bigInteger2.subtract(ONE).gcd(bigInteger);
                        return gcd2.compareTo(ONE) > 0 ? MROutput.provablyCompositeWithFactor(gcd2) : MROutput.access$200();
                    }
                }
            }
            return MROutput.access$000();
        }
        return MROutput.provablyCompositeWithFactor(TWO);
    }

    public static boolean hasAnySmallFactors(BigInteger bigInteger) {
        checkCandidate(bigInteger, "candidate");
        return implHasAnySmallFactors(bigInteger);
    }

    public static boolean isMRProbablePrime(BigInteger bigInteger, SecureRandom secureRandom, int i) {
        checkCandidate(bigInteger, "candidate");
        if (secureRandom == null) {
            throw new IllegalArgumentException("'random' cannot be null");
        }
        if (i < 1) {
            throw new IllegalArgumentException("'iterations' must be > 0");
        }
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

    public static boolean isMRProbablePrimeToBase(BigInteger bigInteger, BigInteger bigInteger2) {
        checkCandidate(bigInteger, "candidate");
        checkCandidate(bigInteger2, "base");
        if (bigInteger2.compareTo(bigInteger.subtract(ONE)) >= 0) {
            throw new IllegalArgumentException("'base' must be < ('candidate' - 1)");
        }
        if (bigInteger.bitLength() == 2) {
            return true;
        }
        BigInteger subtract = bigInteger.subtract(ONE);
        int lowestSetBit = subtract.getLowestSetBit();
        return implMRProbablePrimeToBase(bigInteger, subtract, subtract.shiftRight(lowestSetBit), lowestSetBit, bigInteger2);
    }

    private static void checkCandidate(BigInteger bigInteger, String str) {
        if (bigInteger == null || bigInteger.signum() < 1 || bigInteger.bitLength() < 2) {
            throw new IllegalArgumentException("'" + str + "' must be non-null and >= 2");
        }
    }

    private static boolean implHasAnySmallFactors(BigInteger bigInteger) {
        int intValue = bigInteger.mod(BigInteger.valueOf(223092870)).intValue();
        if (intValue % 2 == 0 || intValue % 3 == 0 || intValue % 5 == 0 || intValue % 7 == 0 || intValue % 11 == 0 || intValue % 13 == 0 || intValue % 17 == 0 || intValue % 19 == 0 || intValue % 23 == 0) {
            return true;
        }
        int intValue2 = bigInteger.mod(BigInteger.valueOf(58642669)).intValue();
        if (intValue2 % 29 == 0 || intValue2 % 31 == 0 || intValue2 % 37 == 0 || intValue2 % 41 == 0 || intValue2 % 43 == 0) {
            return true;
        }
        int intValue3 = bigInteger.mod(BigInteger.valueOf(600662303)).intValue();
        if (intValue3 % 47 == 0 || intValue3 % 53 == 0 || intValue3 % 59 == 0 || intValue3 % 61 == 0 || intValue3 % 67 == 0) {
            return true;
        }
        int intValue4 = bigInteger.mod(BigInteger.valueOf(33984931)).intValue();
        if (intValue4 % 71 == 0 || intValue4 % 73 == 0 || intValue4 % 79 == 0 || intValue4 % 83 == 0) {
            return true;
        }
        int intValue5 = bigInteger.mod(BigInteger.valueOf(89809099)).intValue();
        if (intValue5 % 89 == 0 || intValue5 % 97 == 0 || intValue5 % Opcode.LSUB == 0 || intValue5 % Opcode.DSUB == 0) {
            return true;
        }
        int intValue6 = bigInteger.mod(BigInteger.valueOf(167375713)).intValue();
        if (intValue6 % Opcode.DMUL == 0 || intValue6 % Opcode.LDIV == 0 || intValue6 % Opcode.LREM == 0 || intValue6 % Opcode.LAND == 0) {
            return true;
        }
        int intValue7 = bigInteger.mod(BigInteger.valueOf(371700317)).intValue();
        if (intValue7 % Opcode.LXOR == 0 || intValue7 % Opcode.L2F == 0 || intValue7 % Opcode.F2I == 0 || intValue7 % Opcode.FCMPL == 0) {
            return true;
        }
        int intValue8 = bigInteger.mod(BigInteger.valueOf(645328247)).intValue();
        if (intValue8 % Opcode.DCMPL == 0 || intValue8 % Opcode.IFGT == 0 || intValue8 % Opcode.IF_ICMPGT == 0 || intValue8 % Opcode.GOTO == 0) {
            return true;
        }
        int intValue9 = bigInteger.mod(BigInteger.valueOf(1070560157)).intValue();
        if (intValue9 % Opcode.LRETURN == 0 || intValue9 % Opcode.PUTSTATIC == 0 || intValue9 % Opcode.PUTFIELD == 0 || intValue9 % Opcode.ATHROW == 0) {
            return true;
        }
        int intValue10 = bigInteger.mod(BigInteger.valueOf(1596463769)).intValue();
        return intValue10 % Opcode.INSTANCEOF == 0 || intValue10 % Opcode.MULTIANEWARRAY == 0 || intValue10 % Opcode.IFNONNULL == 0 || intValue10 % SMALL_FACTOR_LIMIT == 0;
    }

    /* JADX WARN: Code restructure failed: missing block: B:20:0x005a, code lost:
        return r10;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static boolean implMRProbablePrimeToBase(java.math.BigInteger r4, java.math.BigInteger r5, java.math.BigInteger r6, int r7, java.math.BigInteger r8) {
        /*
            r0 = r8
            r1 = r6
            r2 = r4
            java.math.BigInteger r0 = r0.modPow(r1, r2)
            r9 = r0
            r0 = r9
            java.math.BigInteger r1 = org.bouncycastle.math.Primes.ONE
            boolean r0 = r0.equals(r1)
            if (r0 != 0) goto L1d
            r0 = r9
            r1 = r5
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L1f
        L1d:
            r0 = 1
            return r0
        L1f:
            r0 = 0
            r10 = r0
            r0 = 1
            r11 = r0
        L25:
            r0 = r11
            r1 = r7
            if (r0 >= r1) goto L58
            r0 = r9
            java.math.BigInteger r1 = org.bouncycastle.math.Primes.TWO
            r2 = r4
            java.math.BigInteger r0 = r0.modPow(r1, r2)
            r9 = r0
            r0 = r9
            r1 = r5
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L45
            r0 = 1
            r10 = r0
            goto L58
        L45:
            r0 = r9
            java.math.BigInteger r1 = org.bouncycastle.math.Primes.ONE
            boolean r0 = r0.equals(r1)
            if (r0 == 0) goto L52
            r0 = 0
            return r0
        L52:
            int r11 = r11 + 1
            goto L25
        L58:
            r0 = r10
            return r0
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.math.Primes.implMRProbablePrimeToBase(java.math.BigInteger, java.math.BigInteger, java.math.BigInteger, int, java.math.BigInteger):boolean");
    }

    private static STOutput implSTRandomPrime(Digest digest, int i, byte[] bArr) {
        int digestSize = digest.getDigestSize();
        if (i < 33) {
            int i2 = 0;
            byte[] bArr2 = new byte[digestSize];
            byte[] bArr3 = new byte[digestSize];
            do {
                hash(digest, bArr, bArr2, 0);
                inc(bArr, 1);
                hash(digest, bArr, bArr3, 0);
                inc(bArr, 1);
                i2++;
                long extract32 = (((extract32(bArr2) ^ extract32(bArr3)) & ((-1) >>> (32 - i))) | (1 << (i - 1)) | 1) & 4294967295L;
                if (isPrime32(extract32)) {
                    return new STOutput(BigInteger.valueOf(extract32), bArr, i2);
                }
            } while (i2 <= 4 * i);
            throw new IllegalStateException("Too many iterations in Shawe-Taylor Random_Prime Routine");
        }
        STOutput implSTRandomPrime = implSTRandomPrime(digest, (i + 3) / 2, bArr);
        BigInteger prime = implSTRandomPrime.getPrime();
        byte[] primeSeed = implSTRandomPrime.getPrimeSeed();
        int primeGenCounter = implSTRandomPrime.getPrimeGenCounter();
        int i3 = (i - 1) / (8 * digestSize);
        BigInteger bit = hashGen(digest, primeSeed, i3 + 1).mod(ONE.shiftLeft(i - 1)).setBit(i - 1);
        BigInteger shiftLeft = prime.shiftLeft(1);
        BigInteger shiftLeft2 = bit.subtract(ONE).divide(shiftLeft).add(ONE).shiftLeft(1);
        int i4 = 0;
        BigInteger add = shiftLeft2.multiply(prime).add(ONE);
        while (true) {
            BigInteger bigInteger = add;
            if (bigInteger.bitLength() > i) {
                shiftLeft2 = ONE.shiftLeft(i - 1).subtract(ONE).divide(shiftLeft).add(ONE).shiftLeft(1);
                bigInteger = shiftLeft2.multiply(prime).add(ONE);
            }
            primeGenCounter++;
            if (implHasAnySmallFactors(bigInteger)) {
                inc(primeSeed, i3 + 1);
            } else {
                BigInteger add2 = hashGen(digest, primeSeed, i3 + 1).mod(bigInteger.subtract(THREE)).add(TWO);
                shiftLeft2 = shiftLeft2.add(BigInteger.valueOf(i4));
                i4 = 0;
                BigInteger modPow = add2.modPow(shiftLeft2, bigInteger);
                if (bigInteger.gcd(modPow.subtract(ONE)).equals(ONE) && modPow.modPow(prime, bigInteger).equals(ONE)) {
                    return new STOutput(bigInteger, primeSeed, primeGenCounter);
                }
            }
            if (primeGenCounter >= (4 * i) + primeGenCounter) {
                throw new IllegalStateException("Too many iterations in Shawe-Taylor Random_Prime Routine");
            }
            i4 += 2;
            add = bigInteger.add(shiftLeft);
        }
    }

    private static int extract32(byte[] bArr) {
        int i = 0;
        int min = Math.min(4, bArr.length);
        for (int i2 = 0; i2 < min; i2++) {
            i |= (bArr[bArr.length - (i2 + 1)] & 255) << (8 * i2);
        }
        return i;
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

    private static void inc(byte[] bArr, int i) {
        int length = bArr.length;
        while (i > 0) {
            length--;
            if (length < 0) {
                return;
            }
            int i2 = i + (bArr[length] & GF2Field.MASK);
            bArr[length] = (byte) i2;
            i = i2 >>> 8;
        }
    }

    private static boolean isPrime32(long j) {
        if ((j >>> 32) != 0) {
            throw new IllegalArgumentException("Size limit exceeded");
        }
        if (j <= 5) {
            return j == 2 || j == 3 || j == 5;
        } else if ((j & 1) == 0 || j % 3 == 0 || j % 5 == 0) {
            return false;
        } else {
            long[] jArr = {1, 7, 11, 13, 17, 19, 23, 29};
            long j2 = 0;
            int i = 1;
            while (true) {
                if (i >= jArr.length) {
                    j2 += 30;
                    if (j2 * j2 >= j) {
                        return true;
                    }
                    i = 0;
                } else if (j % (j2 + jArr[i]) == 0) {
                    return j < 30;
                } else {
                    i++;
                }
            }
        }
    }
}