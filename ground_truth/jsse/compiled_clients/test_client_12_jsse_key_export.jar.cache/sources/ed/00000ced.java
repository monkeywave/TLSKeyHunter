package org.bouncycastle.math.p010ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPointMap;
import org.bouncycastle.math.p010ec.ScaleYNegateXPointMap;

/* renamed from: org.bouncycastle.math.ec.endo.GLVTypeAEndomorphism */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/GLVTypeAEndomorphism.class */
public class GLVTypeAEndomorphism implements GLVEndomorphism {
    protected final GLVTypeAParameters parameters;
    protected final ECPointMap pointMap;

    public GLVTypeAEndomorphism(ECCurve eCCurve, GLVTypeAParameters gLVTypeAParameters) {
        this.parameters = gLVTypeAParameters;
        this.pointMap = new ScaleYNegateXPointMap(eCCurve.fromBigInteger(gLVTypeAParameters.getI()));
    }

    @Override // org.bouncycastle.math.p010ec.endo.GLVEndomorphism
    public BigInteger[] decomposeScalar(BigInteger bigInteger) {
        return EndoUtil.decomposeScalar(this.parameters.getSplitParams(), bigInteger);
    }

    @Override // org.bouncycastle.math.p010ec.endo.ECEndomorphism
    public ECPointMap getPointMap() {
        return this.pointMap;
    }

    @Override // org.bouncycastle.math.p010ec.endo.ECEndomorphism
    public boolean hasEfficientPointMap() {
        return true;
    }
}