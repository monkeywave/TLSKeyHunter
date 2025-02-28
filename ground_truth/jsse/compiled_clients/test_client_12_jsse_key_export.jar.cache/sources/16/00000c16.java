package org.bouncycastle.jce.spec;

import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ECPublicKeySpec.class */
public class ECPublicKeySpec extends ECKeySpec {

    /* renamed from: q */
    private ECPoint f645q;

    public ECPublicKeySpec(ECPoint eCPoint, ECParameterSpec eCParameterSpec) {
        super(eCParameterSpec);
        if (eCPoint.getCurve() != null) {
            this.f645q = eCPoint.normalize();
        } else {
            this.f645q = eCPoint;
        }
    }

    public ECPoint getQ() {
        return this.f645q;
    }
}