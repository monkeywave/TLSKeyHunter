package org.bouncycastle.pqc.crypto.mceliece;

import java.math.BigInteger;
import org.bouncycastle.pqc.math.linearalgebra.BigIntUtils;
import org.bouncycastle.pqc.math.linearalgebra.GF2Vector;
import org.bouncycastle.pqc.math.linearalgebra.IntegerFunctions;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/Conversions.class */
final class Conversions {
    private static final BigInteger ZERO = BigInteger.valueOf(0);
    private static final BigInteger ONE = BigInteger.valueOf(1);

    private Conversions() {
    }

    public static GF2Vector encode(int i, int i2, byte[] bArr) {
        if (i < i2) {
            throw new IllegalArgumentException("n < t");
        }
        BigInteger binomial = IntegerFunctions.binomial(i, i2);
        BigInteger bigInteger = new BigInteger(1, bArr);
        if (bigInteger.compareTo(binomial) >= 0) {
            throw new IllegalArgumentException("Encoded number too large.");
        }
        GF2Vector gF2Vector = new GF2Vector(i);
        int i3 = i;
        int i4 = i2;
        for (int i5 = 0; i5 < i; i5++) {
            binomial = binomial.multiply(BigInteger.valueOf(i3 - i4)).divide(BigInteger.valueOf(i3));
            i3--;
            if (binomial.compareTo(bigInteger) <= 0) {
                gF2Vector.setBit(i5);
                bigInteger = bigInteger.subtract(binomial);
                i4--;
                binomial = i3 == i4 ? ONE : binomial.multiply(BigInteger.valueOf(i4 + 1)).divide(BigInteger.valueOf(i3 - i4));
            }
        }
        return gF2Vector;
    }

    public static byte[] decode(int i, int i2, GF2Vector gF2Vector) {
        if (gF2Vector.getLength() == i && gF2Vector.getHammingWeight() == i2) {
            int[] vecArray = gF2Vector.getVecArray();
            BigInteger binomial = IntegerFunctions.binomial(i, i2);
            BigInteger bigInteger = ZERO;
            int i3 = i;
            int i4 = i2;
            for (int i5 = 0; i5 < i; i5++) {
                binomial = binomial.multiply(BigInteger.valueOf(i3 - i4)).divide(BigInteger.valueOf(i3));
                i3--;
                if ((vecArray[i5 >> 5] & (1 << (i5 & 31))) != 0) {
                    bigInteger = bigInteger.add(binomial);
                    i4--;
                    binomial = i3 == i4 ? ONE : binomial.multiply(BigInteger.valueOf(i4 + 1)).divide(BigInteger.valueOf(i3 - i4));
                }
            }
            return BigIntUtils.toMinimalByteArray(bigInteger);
        }
        throw new IllegalArgumentException("vector has wrong length or hamming weight");
    }

    public static byte[] signConversion(int i, int i2, byte[] bArr) {
        if (i < i2) {
            throw new IllegalArgumentException("n < t");
        }
        BigInteger binomial = IntegerFunctions.binomial(i, i2);
        int bitLength = binomial.bitLength() - 1;
        int i3 = bitLength >> 3;
        int i4 = bitLength & 7;
        if (i4 == 0) {
            i3--;
            i4 = 8;
        }
        int i5 = i >> 3;
        int i6 = i & 7;
        if (i6 == 0) {
            i5--;
            i6 = 8;
        }
        byte[] bArr2 = new byte[i5 + 1];
        if (bArr.length < bArr2.length) {
            System.arraycopy(bArr, 0, bArr2, 0, bArr.length);
            for (int length = bArr.length; length < bArr2.length; length++) {
                bArr2[length] = 0;
            }
        } else {
            System.arraycopy(bArr, 0, bArr2, 0, i5);
            bArr2[i5] = (byte) (((1 << i6) - 1) & bArr[i5]);
        }
        BigInteger bigInteger = ZERO;
        int i7 = i;
        int i8 = i2;
        for (int i9 = 0; i9 < i; i9++) {
            binomial = binomial.multiply(new BigInteger(Integer.toString(i7 - i8))).divide(new BigInteger(Integer.toString(i7)));
            i7--;
            if (((byte) ((1 << (i9 & 7)) & bArr2[i9 >>> 3])) != 0) {
                bigInteger = bigInteger.add(binomial);
                i8--;
                binomial = i7 == i8 ? ONE : binomial.multiply(new BigInteger(Integer.toString(i8 + 1))).divide(new BigInteger(Integer.toString(i7 - i8)));
            }
        }
        byte[] bArr3 = new byte[i3 + 1];
        byte[] byteArray = bigInteger.toByteArray();
        if (byteArray.length < bArr3.length) {
            System.arraycopy(byteArray, 0, bArr3, 0, byteArray.length);
            for (int length2 = byteArray.length; length2 < bArr3.length; length2++) {
                bArr3[length2] = 0;
            }
        } else {
            System.arraycopy(byteArray, 0, bArr3, 0, i3);
            bArr3[i3] = (byte) (((1 << i4) - 1) & byteArray[i3]);
        }
        return bArr3;
    }
}