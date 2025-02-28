package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.KeySpec;

/* loaded from: classes2.dex */
public class GOST3410PrivateKeySpec implements KeySpec {

    /* renamed from: a */
    private BigInteger f978a;

    /* renamed from: p */
    private BigInteger f979p;

    /* renamed from: q */
    private BigInteger f980q;

    /* renamed from: x */
    private BigInteger f981x;

    public GOST3410PrivateKeySpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4) {
        this.f981x = bigInteger;
        this.f979p = bigInteger2;
        this.f980q = bigInteger3;
        this.f978a = bigInteger4;
    }

    public BigInteger getA() {
        return this.f978a;
    }

    public BigInteger getP() {
        return this.f979p;
    }

    public BigInteger getQ() {
        return this.f980q;
    }

    public BigInteger getX() {
        return this.f981x;
    }
}