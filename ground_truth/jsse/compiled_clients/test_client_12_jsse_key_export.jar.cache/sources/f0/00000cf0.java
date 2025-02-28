package org.bouncycastle.math.p010ec.endo;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.endo.GLVTypeBParameters */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/GLVTypeBParameters.class */
public class GLVTypeBParameters {
    protected final BigInteger beta;
    protected final BigInteger lambda;
    protected final ScalarSplitParameters splitParams;

    public GLVTypeBParameters(BigInteger bigInteger, BigInteger bigInteger2, ScalarSplitParameters scalarSplitParameters) {
        this.beta = bigInteger;
        this.lambda = bigInteger2;
        this.splitParams = scalarSplitParameters;
    }

    public BigInteger getBeta() {
        return this.beta;
    }

    public BigInteger getLambda() {
        return this.lambda;
    }

    public ScalarSplitParameters getSplitParams() {
        return this.splitParams;
    }
}