package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ScaleYPointMap */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ScaleYPointMap.class */
public class ScaleYPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleYPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p010ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleY(this.scale);
    }
}