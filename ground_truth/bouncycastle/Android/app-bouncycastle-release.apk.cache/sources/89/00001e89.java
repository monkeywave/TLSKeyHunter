package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class RSAPrivateCrtKeyParameters extends RSAKeyParameters {

    /* renamed from: dP */
    private BigInteger f877dP;

    /* renamed from: dQ */
    private BigInteger f878dQ;

    /* renamed from: e */
    private BigInteger f879e;

    /* renamed from: p */
    private BigInteger f880p;

    /* renamed from: q */
    private BigInteger f881q;
    private BigInteger qInv;

    public RSAPrivateCrtKeyParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5, BigInteger bigInteger6, BigInteger bigInteger7, BigInteger bigInteger8) {
        this(bigInteger, bigInteger2, bigInteger3, bigInteger4, bigInteger5, bigInteger6, bigInteger7, bigInteger8, false);
    }

    public RSAPrivateCrtKeyParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5, BigInteger bigInteger6, BigInteger bigInteger7, BigInteger bigInteger8, boolean z) {
        super(true, bigInteger, bigInteger3, z);
        this.f879e = bigInteger2;
        this.f880p = bigInteger4;
        this.f881q = bigInteger5;
        this.f877dP = bigInteger6;
        this.f878dQ = bigInteger7;
        this.qInv = bigInteger8;
    }

    public BigInteger getDP() {
        return this.f877dP;
    }

    public BigInteger getDQ() {
        return this.f878dQ;
    }

    public BigInteger getP() {
        return this.f880p;
    }

    public BigInteger getPublicExponent() {
        return this.f879e;
    }

    public BigInteger getQ() {
        return this.f881q;
    }

    public BigInteger getQInv() {
        return this.qInv;
    }
}