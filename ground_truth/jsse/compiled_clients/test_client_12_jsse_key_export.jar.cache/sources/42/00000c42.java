package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;

/* renamed from: org.bouncycastle.math.ec.FixedPointCombMultiplier */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/FixedPointCombMultiplier.class */
public class FixedPointCombMultiplier extends AbstractECMultiplier {
    @Override // org.bouncycastle.math.p010ec.AbstractECMultiplier
    protected ECPoint multiplyPositive(ECPoint eCPoint, BigInteger bigInteger) {
        ECCurve curve = eCPoint.getCurve();
        int combSize = FixedPointUtil.getCombSize(curve);
        if (bigInteger.bitLength() > combSize) {
            throw new IllegalStateException("fixed-point comb doesn't support scalars larger than the curve order");
        }
        FixedPointPreCompInfo precompute = FixedPointUtil.precompute(eCPoint);
        ECLookupTable lookupTable = precompute.getLookupTable();
        int width = precompute.getWidth();
        int i = ((combSize + width) - 1) / width;
        ECPoint infinity = curve.getInfinity();
        int i2 = i * width;
        int[] fromBigInteger = Nat.fromBigInteger(i2, bigInteger);
        int i3 = i2 - 1;
        for (int i4 = 0; i4 < i; i4++) {
            int i5 = 0;
            int i6 = i3;
            int i7 = i4;
            while (true) {
                int i8 = i6 - i7;
                if (i8 >= 0) {
                    int i9 = fromBigInteger[i8 >>> 5] >>> (i8 & 31);
                    i5 = ((i5 ^ (i9 >>> 1)) << 1) ^ i9;
                    i6 = i8;
                    i7 = i;
                }
            }
            infinity = infinity.twicePlus(lookupTable.lookup(i5));
        }
        return infinity.add(precompute.getOffset());
    }
}