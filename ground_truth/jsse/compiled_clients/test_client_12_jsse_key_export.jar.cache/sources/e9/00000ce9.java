package org.bouncycastle.math.p010ec.endo;

import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.PreCompInfo;

/* renamed from: org.bouncycastle.math.ec.endo.EndoPreCompInfo */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/EndoPreCompInfo.class */
public class EndoPreCompInfo implements PreCompInfo {
    protected ECEndomorphism endomorphism;
    protected ECPoint mappedPoint;

    public ECEndomorphism getEndomorphism() {
        return this.endomorphism;
    }

    public void setEndomorphism(ECEndomorphism eCEndomorphism) {
        this.endomorphism = eCEndomorphism;
    }

    public ECPoint getMappedPoint() {
        return this.mappedPoint;
    }

    public void setMappedPoint(ECPoint eCPoint) {
        this.mappedPoint = eCPoint;
    }
}