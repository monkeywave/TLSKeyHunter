package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/GOST3410PrivateKeySpec.class */
public class GOST3410PrivateKeySpec implements KeySpec {

    /* renamed from: x */
    private BigInteger f650x;

    /* renamed from: p */
    private BigInteger f651p;

    /* renamed from: q */
    private BigInteger f652q;

    /* renamed from: a */
    private BigInteger f653a;

    public GOST3410PrivateKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f650x = bigInteger;
        this.f651p = bigInteger2;
        this.f652q = bigInteger3;
        this.f653a = bigInteger4;
    }

    public BigInteger getX() {
        return this.f650x;
    }

    public BigInteger getP() {
        return this.f651p;
    }

    public BigInteger getQ() {
        return this.f652q;
    }

    public BigInteger getA() {
        return this.f653a;
    }
}