package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.ScaleYNegateXPointMap */
/* loaded from: classes2.dex */
public class ScaleYNegateXPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleYNegateXPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p016ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleYNegateX(this.scale);
    }
}