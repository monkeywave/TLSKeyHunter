package org.bouncycastle.math.p016ec;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.math.ec.AbstractECMultiplier */
/* loaded from: classes2.dex */
public abstract class AbstractECMultiplier implements ECMultiplier {
    protected ECPoint checkResult(ECPoint eCPoint) {
        return ECAlgorithms.implCheckResult(eCPoint);
    }

    @Override // org.bouncycastle.math.p016ec.ECMultiplier
    public ECPoint multiply(ECPoint eCPoint, BigInteger bigInteger) {
        int signum = bigInteger.signum();
        if (signum == 0 || eCPoint.isInfinity()) {
            return eCPoint.getCurve().getInfinity();
        }
        ECPoint multiplyPositive = multiplyPositive(eCPoint, bigInteger.abs());
        if (signum <= 0) {
            multiplyPositive = multiplyPositive.negate();
        }
        return checkResult(multiplyPositive);
    }

    protected abstract ECPoint multiplyPositive(ECPoint eCPoint, BigInteger bigInteger);
}