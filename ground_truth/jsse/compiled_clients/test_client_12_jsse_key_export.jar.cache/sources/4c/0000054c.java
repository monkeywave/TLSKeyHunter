package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.Integers;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DHPublicKeyParameters.class */
public class DHPublicKeyParameters extends DHKeyParameters {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /* renamed from: y */
    private BigInteger f521y;

    public DHPublicKeyParameters(BigInteger bigInteger, DHParameters dHParameters) {
        super(false, dHParameters);
        this.f521y = validate(bigInteger, dHParameters);
    }

    private BigInteger validate(BigInteger bigInteger, DHParameters dHParameters) {
        if (bigInteger == null) {
            throw new NullPointerException("y value cannot be null");
        }
        BigInteger p = dHParameters.getP();
        if (bigInteger.compareTo(TWO) < 0 || bigInteger.compareTo(p.subtract(TWO)) > 0) {
            throw new IllegalArgumentException("invalid DH public key");
        }
        BigInteger q = dHParameters.getQ();
        if (q == null) {
            return bigInteger;
        }
        if (p.testBit(0) && p.bitLength() - 1 == q.bitLength() && p.shiftRight(1).equals(q)) {
            if (1 == legendre(bigInteger, p)) {
                return bigInteger;
            }
        } else if (ONE.equals(bigInteger.modPow(q, p))) {
            return bigInteger;
        }
        throw new IllegalArgumentException("Y value does not appear to be in correct group");
    }

    public BigInteger getY() {
        return this.f521y;
    }

    @Override // org.bouncycastle.crypto.params.DHKeyParameters
    public int hashCode() {
        return this.f521y.hashCode() ^ super.hashCode();
    }

    @Override // org.bouncycastle.crypto.params.DHKeyParameters
    public boolean equals(Object obj) {
        return (obj instanceof DHPublicKeyParameters) && ((DHPublicKeyParameters) obj).getY().equals(this.f521y) && super.equals(obj);
    }

    private static int legendre(BigInteger bigInteger, BigInteger bigInteger2) {
        int bitLength = bigInteger2.bitLength();
        int[] fromBigInteger = Nat.fromBigInteger(bitLength, bigInteger);
        int[] fromBigInteger2 = Nat.fromBigInteger(bitLength, bigInteger2);
        int i = 0;
        int length = fromBigInteger2.length;
        while (true) {
            if (fromBigInteger[0] == 0) {
                Nat.shiftDownWord(length, fromBigInteger, 0);
            } else {
                int numberOfTrailingZeros = Integers.numberOfTrailingZeros(fromBigInteger[0]);
                if (numberOfTrailingZeros > 0) {
                    Nat.shiftDownBits(length, fromBigInteger, numberOfTrailingZeros, 0);
                    int i2 = fromBigInteger2[0];
                    i ^= (i2 ^ (i2 >>> 1)) & (numberOfTrailingZeros << 1);
                }
                int compare = Nat.compare(length, fromBigInteger, fromBigInteger2);
                if (compare == 0) {
                    break;
                }
                if (compare < 0) {
                    i ^= fromBigInteger[0] & fromBigInteger2[0];
                    int[] iArr = fromBigInteger;
                    fromBigInteger = fromBigInteger2;
                    fromBigInteger2 = iArr;
                }
                while (fromBigInteger[length - 1] == 0) {
                    length--;
                }
                Nat.sub(length, fromBigInteger, fromBigInteger2, fromBigInteger);
            }
        }
        if (Nat.isOne(length, fromBigInteger2)) {
            return 1 - (i & 2);
        }
        return 0;
    }
}