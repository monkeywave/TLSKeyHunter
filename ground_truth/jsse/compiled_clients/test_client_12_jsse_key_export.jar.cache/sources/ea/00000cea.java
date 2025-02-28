package org.bouncycastle.math.p010ec.endo;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.PreCompCallback;
import org.bouncycastle.math.p010ec.PreCompInfo;

/* renamed from: org.bouncycastle.math.ec.endo.EndoUtil */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/endo/EndoUtil.class */
public abstract class EndoUtil {
    public static final String PRECOMP_NAME = "bc_endo";

    public static BigInteger[] decomposeScalar(ScalarSplitParameters scalarSplitParameters, BigInteger bigInteger) {
        int bits = scalarSplitParameters.getBits();
        BigInteger calculateB = calculateB(bigInteger, scalarSplitParameters.getG1(), bits);
        BigInteger calculateB2 = calculateB(bigInteger, scalarSplitParameters.getG2(), bits);
        return new BigInteger[]{bigInteger.subtract(calculateB.multiply(scalarSplitParameters.getV1A()).add(calculateB2.multiply(scalarSplitParameters.getV2A()))), calculateB.multiply(scalarSplitParameters.getV1B()).add(calculateB2.multiply(scalarSplitParameters.getV2B())).negate()};
    }

    public static ECPoint mapPoint(final ECEndomorphism eCEndomorphism, final ECPoint eCPoint) {
        return ((EndoPreCompInfo) eCPoint.getCurve().precompute(eCPoint, PRECOMP_NAME, new PreCompCallback() { // from class: org.bouncycastle.math.ec.endo.EndoUtil.1
            @Override // org.bouncycastle.math.p010ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo preCompInfo) {
                EndoPreCompInfo endoPreCompInfo = preCompInfo instanceof EndoPreCompInfo ? (EndoPreCompInfo) preCompInfo : null;
                if (checkExisting(endoPreCompInfo, ECEndomorphism.this)) {
                    return endoPreCompInfo;
                }
                ECPoint map = ECEndomorphism.this.getPointMap().map(eCPoint);
                EndoPreCompInfo endoPreCompInfo2 = new EndoPreCompInfo();
                endoPreCompInfo2.setEndomorphism(ECEndomorphism.this);
                endoPreCompInfo2.setMappedPoint(map);
                return endoPreCompInfo2;
            }

            private boolean checkExisting(EndoPreCompInfo endoPreCompInfo, ECEndomorphism eCEndomorphism2) {
                return (null == endoPreCompInfo || endoPreCompInfo.getEndomorphism() != eCEndomorphism2 || endoPreCompInfo.getMappedPoint() == null) ? false : true;
            }
        })).getMappedPoint();
    }

    private static BigInteger calculateB(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        boolean z = bigInteger2.signum() < 0;
        BigInteger multiply = bigInteger.multiply(bigInteger2.abs());
        boolean testBit = multiply.testBit(i - 1);
        BigInteger shiftRight = multiply.shiftRight(i);
        if (testBit) {
            shiftRight = shiftRight.add(ECConstants.ONE);
        }
        return z ? shiftRight.negate() : shiftRight;
    }
}