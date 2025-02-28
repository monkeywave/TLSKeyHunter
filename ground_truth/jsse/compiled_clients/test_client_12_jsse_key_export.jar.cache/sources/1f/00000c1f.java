package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/GOST3410PublicKeyParameterSetSpec.class */
public class GOST3410PublicKeyParameterSetSpec {

    /* renamed from: p */
    private BigInteger f654p;

    /* renamed from: q */
    private BigInteger f655q;

    /* renamed from: a */
    private BigInteger f656a;

    public GOST3410PublicKeyParameterSetSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f654p = bigInteger;
        this.f655q = bigInteger2;
        this.f656a = bigInteger3;
    }

    public BigInteger getP() {
        return this.f654p;
    }

    public BigInteger getQ() {
        return this.f655q;
    }

    public BigInteger getA() {
        return this.f656a;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410PublicKeyParameterSetSpec) {
            GOST3410PublicKeyParameterSetSpec gOST3410PublicKeyParameterSetSpec = (GOST3410PublicKeyParameterSetSpec) obj;
            return this.f656a.equals(gOST3410PublicKeyParameterSetSpec.f656a) && this.f654p.equals(gOST3410PublicKeyParameterSetSpec.f654p) && this.f655q.equals(gOST3410PublicKeyParameterSetSpec.f655q);
        }
        return false;
    }

    public int hashCode() {
        return (this.f656a.hashCode() ^ this.f654p.hashCode()) ^ this.f655q.hashCode();
    }
}