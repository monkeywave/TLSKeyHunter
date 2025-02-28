package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ScaleYNegateXPointMap */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ScaleYNegateXPointMap.class */
public class ScaleYNegateXPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleYNegateXPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p010ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleYNegateX(this.scale);
    }
}