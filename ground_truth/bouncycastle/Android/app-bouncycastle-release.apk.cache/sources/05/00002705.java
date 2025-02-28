package org.bouncycastle.math.p016ec;

import java.math.BigInteger;
import org.bouncycastle.math.raw.Nat;

/* renamed from: org.bouncycastle.math.ec.FixedPointCombMultiplier */
/* loaded from: classes2.dex */
public class FixedPointCombMultiplier extends AbstractECMultiplier {
    @Override // org.bouncycastle.math.p016ec.AbstractECMultiplier
    protected ECPoint multiplyPositive(ECPoint eCPoint, BigInteger bigInteger) {
        int combSize;
        ECCurve curve = eCPoint.getCurve();
        if (bigInteger.bitLength() <= FixedPointUtil.getCombSize(curve)) {
            FixedPointPreCompInfo precompute = FixedPointUtil.precompute(eCPoint);
            ECLookupTable lookupTable = precompute.getLookupTable();
            int width = precompute.getWidth();
            int i = ((combSize + width) - 1) / width;
            ECPoint infinity = curve.getInfinity();
            int i2 = width * i;
            int[] fromBigInteger = Nat.fromBigInteger(i2, bigInteger);
            int i3 = i2 - 1;
            for (int i4 = 0; i4 < i; i4++) {
                int i5 = 0;
                for (int i6 = i3 - i4; i6 >= 0; i6 -= i) {
                    int i7 = fromBigInteger[i6 >>> 5] >>> (i6 & 31);
                    i5 = ((i5 ^ (i7 >>> 1)) << 1) ^ i7;
                }
                infinity = infinity.twicePlus(lookupTable.lookup(i5));
            }
            return infinity.add(precompute.getOffset());
        }
        throw new IllegalStateException("fixed-point comb doesn't support scalars larger than the curve order");
    }
}