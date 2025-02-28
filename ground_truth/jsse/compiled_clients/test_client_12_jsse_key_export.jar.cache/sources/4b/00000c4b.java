package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ScaleXPointMap */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ScaleXPointMap.class */
public class ScaleXPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleXPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p010ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleX(this.scale);
    }
}