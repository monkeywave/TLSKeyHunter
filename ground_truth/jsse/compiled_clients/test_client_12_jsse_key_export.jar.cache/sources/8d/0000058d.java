package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/RSAPrivateCrtKeyParameters.class */
public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {

    /* renamed from: e */
    private BigInteger f559e;

    /* renamed from: p */
    private BigInteger f560p;

    /* renamed from: q */
    private BigInteger f561q;

    /* renamed from: dP */
    private BigInteger f562dP;

    /* renamed from: dQ */
    private BigInteger f563dQ;
    private BigInteger qInv;

    public RSAPrivateCrtKeyParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5, BigInteger bigInteger6, BigInteger bigInteger7, BigInteger bigInteger8) {
        super(true, bigInteger, bigInteger3);
        this.f559e = bigInteger2;
        this.f560p = bigInteger4;
        this.f561q = bigInteger5;
        this.f562dP = bigInteger6;
        this.f563dQ = bigInteger7;
        this.qInv = bigInteger8;
    }

    public BigInteger getPublicExponent() {
        return this.f559e;
    }

    public BigInteger getP() {
        return this.f560p;
    }

    public BigInteger getQ() {
        return this.f561q;
    }

    public BigInteger getDP() {
        return this.f562dP;
    }

    public BigInteger getDQ() {
        return this.f563dQ;
    }

    public BigInteger getQInv() {
        return this.qInv;
    }
}