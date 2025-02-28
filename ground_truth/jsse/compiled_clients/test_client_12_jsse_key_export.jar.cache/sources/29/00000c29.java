package org.bouncycastle.math.p010ec;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.AbstractECMultiplier */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/AbstractECMultiplier.class */
public abstract class AbstractECMultiplier implements ECMultiplier {
    @Override // org.bouncycastle.math.p010ec.ECMultiplier
    public ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger) {
        int signum = bigInteger.signum();
        if (signum == 0 || eCPoint.isInfinity()) {
            return eCPoint.getCurve().getInfinity();
        }
        ECPoint multiplyPositive = multiplyPositive(eCPoint, bigInteger.abs());
        return checkResult(signum > 0 ? multiplyPositive : multiplyPositive.negate());
    }

    protected abstract ECPoint multiplyPositive(ECPoint eCPoint, BigInteger bigInteger);

    protected ECPoint checkResult(ECPoint eCPoint) {
        return ECAlgorithms.implCheckResult(eCPoint);
    }
}