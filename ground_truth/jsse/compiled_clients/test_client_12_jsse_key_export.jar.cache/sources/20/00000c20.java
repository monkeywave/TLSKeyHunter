package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/GOST3410PublicKeySpec.class */
public class GOST3410PublicKeySpec implements KeySpec {

    /* renamed from: y */
    private BigInteger f657y;

    /* renamed from: p */
    private BigInteger f658p;

    /* renamed from: q */
    private BigInteger f659q;

    /* renamed from: a */
    private BigInteger f660a;

    public GOST3410PublicKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f657y = bigInteger;
        this.f658p = bigInteger2;
        this.f659q = bigInteger3;
        this.f660a = bigInteger4;
    }

    public BigInteger getY() {
        return this.f657y;
    }

    public BigInteger getP() {
        return this.f658p;
    }

    public BigInteger getQ() {
        return this.f659q;
    }

    public BigInteger getA() {
        return this.f660a;
    }
}