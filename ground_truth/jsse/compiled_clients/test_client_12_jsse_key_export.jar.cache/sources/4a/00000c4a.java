package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ScaleXNegateYPointMap */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ScaleXNegateYPointMap.class */
public class ScaleXNegateYPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleXNegateYPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p010ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleXNegateY(this.scale);
    }
}