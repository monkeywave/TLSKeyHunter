package org.bouncycastle.tls.crypto.impl.jcajce.srp;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.BigIntegers;

/* loaded from: classes2.dex */
class SRP6Util {
    private static final byte[] colon = {58};
    private static BigInteger ZERO = BigInteger.valueOf(0);
    private static BigInteger ONE = BigInteger.valueOf(1);

    SRP6Util() {
    }

    public static BigInteger calculateK(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2) {
        return hashPaddedPair(tlsHash, bigInteger, bigInteger, bigInteger2);
    }

    public static BigInteger calculateKey(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2) {
        byte[] padded = getPadded(bigInteger2, (bigInteger.bitLength() + 7) / 8);
        tlsHash.update(padded, 0, padded.length);
        return new BigInteger(1, tlsHash.calculateHash());
    }

    public static BigInteger calculateM1(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        return hashPaddedTriplet(tlsHash, bigInteger, bigInteger2, bigInteger3, bigInteger4);
    }

    public static BigInteger calculateM2(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        return hashPaddedTriplet(tlsHash, bigInteger, bigInteger2, bigInteger3, bigInteger4);
    }

    public static BigInteger calculateU(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        return hashPaddedPair(tlsHash, bigInteger, bigInteger2, bigInteger3);
    }

    public static BigInteger calculateX(TlsHash tlsHash, BigInteger bigInteger, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        tlsHash.update(bArr2, 0, bArr2.length);
        tlsHash.update(colon, 0, 1);
        tlsHash.update(bArr3, 0, bArr3.length);
        byte[] calculateHash = tlsHash.calculateHash();
        tlsHash.update(bArr, 0, bArr.length);
        tlsHash.update(calculateHash, 0, calculateHash.length);
        return new BigInteger(1, tlsHash.calculateHash());
    }

    public static BigInteger generatePrivateValue(BigInteger bigInteger, BigInteger bigInteger2, SecureRandom secureRandom) {
        return BigIntegers.createRandomInRange(ONE.shiftLeft(Math.min(256, bigInteger.bitLength() / 2) - 1), bigInteger.subtract(ONE), secureRandom);
    }

    private static byte[] getPadded(BigInteger bigInteger, int i) {
        byte[] asUnsignedByteArray = BigIntegers.asUnsignedByteArray(bigInteger);
        if (asUnsignedByteArray.length < i) {
            byte[] bArr = new byte[i];
            System.arraycopy(asUnsignedByteArray, 0, bArr, i - asUnsignedByteArray.length, asUnsignedByteArray.length);
            return bArr;
        }
        return asUnsignedByteArray;
    }

    private static BigInteger hashPaddedPair(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        int bitLength = (bigInteger.bitLength() + 7) / 8;
        byte[] padded = getPadded(bigInteger2, bitLength);
        byte[] padded2 = getPadded(bigInteger3, bitLength);
        tlsHash.update(padded, 0, padded.length);
        tlsHash.update(padded2, 0, padded2.length);
        return new BigInteger(1, tlsHash.calculateHash());
    }

    private static BigInteger hashPaddedTriplet(TlsHash tlsHash, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        int bitLength = (bigInteger.bitLength() + 7) / 8;
        byte[] padded = getPadded(bigInteger2, bitLength);
        byte[] padded2 = getPadded(bigInteger3, bitLength);
        byte[] padded3 = getPadded(bigInteger4, bitLength);
        tlsHash.update(padded, 0, padded.length);
        tlsHash.update(padded2, 0, padded2.length);
        tlsHash.update(padded3, 0, padded3.length);
        return new BigInteger(1, tlsHash.calculateHash());
    }

    public static BigInteger validatePublicValue(BigInteger bigInteger, BigInteger bigInteger2) throws IllegalArgumentException {
        BigInteger mod = bigInteger2.mod(bigInteger);
        if (mod.equals(ZERO)) {
            throw new IllegalArgumentException("Invalid public value: 0");
        }
        return mod;
    }
}