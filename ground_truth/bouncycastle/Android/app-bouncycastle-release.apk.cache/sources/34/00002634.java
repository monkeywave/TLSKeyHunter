package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class GOST3410PublicKeyParameterSetSpec {

    /* renamed from: a */
    private BigInteger f982a;

    /* renamed from: p */
    private BigInteger f983p;

    /* renamed from: q */
    private BigInteger f984q;

    public GOST3410PublicKeyParameterSetSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f983p = bigInteger;
        this.f984q = bigInteger2;
        this.f982a = bigInteger3;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410PublicKeyParameterSetSpec) {
            GOST3410PublicKeyParameterSetSpec gOST3410PublicKeyParameterSetSpec = (GOST3410PublicKeyParameterSetSpec) obj;
            return this.f982a.equals(gOST3410PublicKeyParameterSetSpec.f982a) && this.f983p.equals(gOST3410PublicKeyParameterSetSpec.f983p) && this.f984q.equals(gOST3410PublicKeyParameterSetSpec.f984q);
        }
        return false;
    }

    public BigInteger getA() {
        return this.f982a;
    }

    public BigInteger getP() {
        return this.f983p;
    }

    public BigInteger getQ() {
        return this.f984q;
    }

    public int hashCode() {
        return (this.f982a.hashCode() ^ this.f983p.hashCode()) ^ this.f984q.hashCode();
    }
}