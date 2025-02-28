package org.bouncycastle.math.p016ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECPointMap;
import org.bouncycastle.math.p016ec.ScaleYNegateXPointMap;

/* renamed from: org.bouncycastle.math.ec.endo.GLVTypeAEndomorphism */
/* loaded from: classes2.dex */
public class GLVTypeAEndomorphism implements GLVEndomorphism {
    protected final GLVTypeAParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeAEndomorphism(ECCurve eCCurve, GLVTypeAParameters gLVTypeAParameters) {
        this.parameters = gLVTypeAParameters;
        this.pointMap = new ScaleYNegateXPointMap(eCCurve.fromBigInteger(gLVTypeAParameters.getI()));
    }

    @Override // org.bouncycastle.math.p016ec.endo.GLVEndomorphism
    public BigInteger[] decomposeScalar(BigInteger bigInteger) {
        return EndoUtil.decomposeScalar(this.parameters.getSplitParams(), bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.endo.ECEndomorphism
    public ECPointMap getPointMap() {
        return this.pointMap;
    }

    @Override // org.bouncycastle.math.p016ec.endo.ECEndomorphism
    public boolean hasEfficientPointMap() {
        return true;
    }
}