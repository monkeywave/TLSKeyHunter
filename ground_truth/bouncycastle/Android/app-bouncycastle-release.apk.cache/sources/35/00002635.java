package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/* loaded from: classes2.dex */
public class GOST3410PublicKeySpec implements KeySpec {

    /* renamed from: a */
    private BigInteger f985a;

    /* renamed from: p */
    private BigInteger f986p;

    /* renamed from: q */
    private BigInteger f987q;

    /* renamed from: y */
    private BigInteger f988y;

    public GOST3410PublicKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f988y = bigInteger;
        this.f986p = bigInteger2;
        this.f987q = bigInteger3;
        this.f985a = bigInteger4;
    }

    public BigInteger getA() {
        return this.f985a;
    }

    public BigInteger getP() {
        return this.f986p;
    }

    public BigInteger getQ() {
        return this.f987q;
    }

    public BigInteger getY() {
        return this.f988y;
    }
}