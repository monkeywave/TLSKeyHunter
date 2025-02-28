package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.ScaleXNegateYPointMap */
/* loaded from: classes2.dex */
public class ScaleXNegateYPointMap implements ECPointMap {
    protected final ECFieldElement scale;

    public ScaleXNegateYPointMap(ECFieldElement eCFieldElement) {
        this.scale = eCFieldElement;
    }

    @Override // org.bouncycastle.math.p016ec.ECPointMap
    public ECPoint map(ECPoint eCPoint) {
        return eCPoint.scaleXNegateY(this.scale);
    }
}