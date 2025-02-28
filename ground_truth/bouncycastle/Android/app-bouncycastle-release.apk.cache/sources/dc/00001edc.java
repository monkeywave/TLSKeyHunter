package org.bouncycastle.crypto.tls;

import java.math.BigInteger;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.CryptoServicePurpose;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.constraints.ConstraintUtils;
import org.bouncycastle.crypto.constraints.DefaultServiceProperties;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public abstract class TlsRsaKeyExchange {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    public static final int PRE_MASTER_SECRET_LENGTH = 48;

    private TlsRsaKeyExchange() {
    }

    private static int caddTo(int i, int i2, byte[] bArr, byte[] bArr2) {
        int i3 = i2 & 255;
        int i4 = 0;
        for (int i5 = i - 1; i5 >= 0; i5--) {
            int i6 = i4 + (bArr2[i5] & UByte.MAX_VALUE) + (bArr[i5] & i3);
            bArr2[i5] = (byte) i6;
            i4 = i6 >>> 8;
        }
        return i4;
    }

    private static int checkPkcs1Encoding2(byte[] bArr, int i, int i2) {
        int i3 = (i - i2) - 10;
        int length = bArr.length - i;
        int length2 = (bArr.length - 1) - i2;
        for (int i4 = 0; i4 < length; i4++) {
            i3 |= -(bArr[i4] & 255);
        }
        int i5 = -((bArr[length] & 255) ^ 2);
        while (true) {
            i5 |= i3;
            length++;
            if (length >= length2) {
                return ((-(bArr[length2] & 255)) | i5) >> 31;
            }
            i3 = (bArr[length] & 255) - 1;
        }
    }

    private static BigInteger convertInput(BigInteger bigInteger, byte[] bArr, int i, int i2) {
        BigInteger fromUnsignedByteArray = BigIntegers.fromUnsignedByteArray(bArr, i, i2);
        if (fromUnsignedByteArray.compareTo(bigInteger) < 0) {
            return fromUnsignedByteArray;
        }
        throw new DataLengthException("input too large for RSA cipher.");
    }

    public static byte[] decryptPreMasterSecret(byte[] bArr, int i, int i2, RSAKeyParameters rSAKeyParameters, int i3, SecureRandom secureRandom) {
        if (bArr == null || i2 < 1 || i2 > getInputLimit(rSAKeyParameters) || i < 0 || i > bArr.length - i2) {
            throw new IllegalArgumentException("input not a valid EncryptedPreMasterSecret");
        }
        if (rSAKeyParameters.isPrivate()) {
            BigInteger modulus = rSAKeyParameters.getModulus();
            int bitLength = modulus.bitLength();
            if (bitLength >= 512) {
                CryptoServicesRegistrar.checkConstraints(new DefaultServiceProperties("RSA", ConstraintUtils.bitsOfSecurityFor(modulus), rSAKeyParameters, CryptoServicePurpose.DECRYPTION));
                if ((i3 & 65535) == i3) {
                    SecureRandom secureRandom2 = CryptoServicesRegistrar.getSecureRandom(secureRandom);
                    byte[] bArr2 = new byte[48];
                    secureRandom2.nextBytes(bArr2);
                    try {
                        byte[] rsaBlinded = rsaBlinded(rSAKeyParameters, convertInput(modulus, bArr, i, i2), secureRandom2);
                        int length = rsaBlinded.length - 48;
                        int checkPkcs1Encoding2 = checkPkcs1Encoding2(rsaBlinded, (bitLength - 1) / 8, 48) | ((-((Pack.bigEndianToShort(rsaBlinded, length) ^ i3) & 65535)) >> 31);
                        for (int i4 = 0; i4 < 48; i4++) {
                            bArr2[i4] = (byte) ((bArr2[i4] & checkPkcs1Encoding2) | (rsaBlinded[length + i4] & (~checkPkcs1Encoding2)));
                        }
                        Arrays.fill(rsaBlinded, (byte) 0);
                    } catch (Exception unused) {
                    }
                    return bArr2;
                }
                throw new IllegalArgumentException("'protocolVersion' must be a 16 bit value");
            }
            throw new IllegalArgumentException("'privateKey' must be at least 512 bits");
        }
        throw new IllegalArgumentException("'privateKey' must be an RSA private key");
    }

    public static int getInputLimit(RSAKeyParameters rSAKeyParameters) {
        return (rSAKeyParameters.getModulus().bitLength() + 7) / 8;
    }

    private static BigInteger rsa(RSAKeyParameters rSAKeyParameters, BigInteger bigInteger) {
        return bigInteger.modPow(rSAKeyParameters.getExponent(), rSAKeyParameters.getModulus());
    }

    private static byte[] rsaBlinded(RSAKeyParameters rSAKeyParameters, BigInteger bigInteger, SecureRandom secureRandom) {
        RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters;
        BigInteger publicExponent;
        BigInteger modulus = rSAKeyParameters.getModulus();
        int bitLength = (modulus.bitLength() / 8) + 1;
        if (!(rSAKeyParameters instanceof RSAPrivateCrtKeyParameters) || (publicExponent = (rSAPrivateCrtKeyParameters = (RSAPrivateCrtKeyParameters) rSAKeyParameters).getPublicExponent()) == null) {
            return toBytes(rsa(rSAKeyParameters, bigInteger), bitLength);
        }
        BigInteger bigInteger2 = ONE;
        BigInteger createRandomInRange = BigIntegers.createRandomInRange(bigInteger2, modulus.subtract(bigInteger2), secureRandom);
        BigInteger modPow = createRandomInRange.modPow(publicExponent, modulus);
        BigInteger modOddInverse = BigIntegers.modOddInverse(modulus, createRandomInRange);
        BigInteger rsaCrt = rsaCrt(rSAPrivateCrtKeyParameters, modPow.multiply(bigInteger).mod(modulus));
        BigInteger mod = modOddInverse.add(bigInteger2).multiply(rsaCrt).mod(modulus);
        byte[] bytes = toBytes(rsaCrt, bitLength);
        byte[] bytes2 = toBytes(modulus, bitLength);
        byte[] bytes3 = toBytes(mod, bitLength);
        caddTo(bitLength, subFrom(bitLength, bytes, bytes3), bytes2, bytes3);
        return bytes3;
    }

    private static BigInteger rsaCrt(RSAPrivateCrtKeyParameters rSAPrivateCrtKeyParameters, BigInteger bigInteger) {
        BigInteger publicExponent = rSAPrivateCrtKeyParameters.getPublicExponent();
        BigInteger p = rSAPrivateCrtKeyParameters.getP();
        BigInteger q = rSAPrivateCrtKeyParameters.getQ();
        BigInteger dp = rSAPrivateCrtKeyParameters.getDP();
        BigInteger dq = rSAPrivateCrtKeyParameters.getDQ();
        BigInteger qInv = rSAPrivateCrtKeyParameters.getQInv();
        BigInteger modPow = bigInteger.remainder(p).modPow(dp, p);
        BigInteger modPow2 = bigInteger.remainder(q).modPow(dq, q);
        BigInteger add = modPow.subtract(modPow2).multiply(qInv).mod(p).multiply(q).add(modPow2);
        if (add.modPow(publicExponent, rSAPrivateCrtKeyParameters.getModulus()).equals(bigInteger)) {
            return add;
        }
        throw new IllegalStateException("RSA engine faulty decryption/signing detected");
    }

    private static int subFrom(int i, byte[] bArr, byte[] bArr2) {
        int i2 = 0;
        for (int i3 = i - 1; i3 >= 0; i3--) {
            int i4 = i2 + ((bArr2[i3] & UByte.MAX_VALUE) - (bArr[i3] & UByte.MAX_VALUE));
            bArr2[i3] = (byte) i4;
            i2 = i4 >> 8;
        }
        return i2;
    }

    private static byte[] toBytes(BigInteger bigInteger, int i) {
        byte[] byteArray = bigInteger.toByteArray();
        byte[] bArr = new byte[i];
        System.arraycopy(byteArray, 0, bArr, i - byteArray.length, byteArray.length);
        return bArr;
    }
}