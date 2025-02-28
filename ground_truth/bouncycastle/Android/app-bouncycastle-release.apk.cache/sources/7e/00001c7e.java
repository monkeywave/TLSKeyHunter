package org.bouncycastle.crypto.agreement.jpake;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class JPAKEPrimeOrderGroup {

    /* renamed from: g */
    private final BigInteger f343g;

    /* renamed from: p */
    private final BigInteger f344p;

    /* renamed from: q */
    private final BigInteger f345q;

    public JPAKEPrimeOrderGroup(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this(bigInteger, bigInteger2, bigInteger3, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public JPAKEPrimeOrderGroup(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, boolean z) {
        JPAKEUtil.validateNotNull(bigInteger, "p");
        JPAKEUtil.validateNotNull(bigInteger2, "q");
        JPAKEUtil.validateNotNull(bigInteger3, "g");
        if (!z) {
            if (!bigInteger.subtract(JPAKEUtil.ONE).mod(bigInteger2).equals(JPAKEUtil.ZERO)) {
                throw new IllegalArgumentException("p-1 must be evenly divisible by q");
            }
            if (bigInteger3.compareTo(BigInteger.valueOf(2L)) == -1 || bigInteger3.compareTo(bigInteger.subtract(JPAKEUtil.ONE)) == 1) {
                throw new IllegalArgumentException("g must be in [2, p-1]");
            }
            if (!bigInteger3.modPow(bigInteger2, bigInteger).equals(JPAKEUtil.ONE)) {
                throw new IllegalArgumentException("g^q mod p must equal 1");
            }
            if (!bigInteger.isProbablePrime(20)) {
                throw new IllegalArgumentException("p must be prime");
            }
            if (!bigInteger2.isProbablePrime(20)) {
                throw new IllegalArgumentException("q must be prime");
            }
        }
        this.f344p = bigInteger;
        this.f345q = bigInteger2;
        this.f343g = bigInteger3;
    }

    public BigInteger getG() {
        return this.f343g;
    }

    public BigInteger getP() {
        return this.f344p;
    }

    public BigInteger getQ() {
        return this.f345q;
    }
}