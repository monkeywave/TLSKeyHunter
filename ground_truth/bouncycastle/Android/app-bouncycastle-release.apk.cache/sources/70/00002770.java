package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.AbstractECLookupTable;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECLookupTable;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT131R2Curve */
/* loaded from: classes2.dex */
public class SecT131R2Curve extends ECCurve.AbstractF2m {
    private static final ECFieldElement[] SECT131R2_AFFINE_ZS = {new SecT131FieldElement(ECConstants.ONE)};
    private static final int SECT131R2_DEFAULT_COORDS = 6;
    protected SecT131R2Point infinity;

    public SecT131R2Curve() {
        super(131, 2, 3, 8);
        this.infinity = new SecT131R2Point(this, null, null);
        this.f1000a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("03E5A88919D7CAFCBF415F07C2176573B2")));
        this.f1001b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("04B8266A46C55657AC734CE38F018F2192")));
        this.order = new BigInteger(1, Hex.decodeStrict("0400000000000000016954A233049BA98F"));
        this.cofactor = BigInteger.valueOf(2L);
        this.coord = 6;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecT131R2Curve();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final long[] jArr = new long[i2 * 6];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat192.copy64(((SecT131FieldElement) eCPoint.getRawXCoord()).f1091x, 0, jArr, i3);
            Nat192.copy64(((SecT131FieldElement) eCPoint.getRawYCoord()).f1091x, 0, jArr, i3 + 3);
            i3 += 6;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecT131R2Curve.1
            private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                return SecT131R2Curve.this.createRawPoint(new SecT131FieldElement(jArr2), new SecT131FieldElement(jArr3), SecT131R2Curve.SECT131R2_AFFINE_ZS);
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i5) {
                long[] create64 = Nat192.create64();
                long[] create642 = Nat192.create64();
                int i6 = 0;
                for (int i7 = 0; i7 < i2; i7++) {
                    long j = ((i7 ^ i5) - 1) >> 31;
                    for (int i8 = 0; i8 < 3; i8++) {
                        long j2 = create64[i8];
                        long[] jArr2 = jArr;
                        create64[i8] = j2 ^ (jArr2[i6 + i8] & j);
                        create642[i8] = create642[i8] ^ (jArr2[(i6 + 3) + i8] & j);
                    }
                    i6 += 6;
                }
                return createPoint(create64, create642);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i5) {
                long[] create64 = Nat192.create64();
                long[] create642 = Nat192.create64();
                int i6 = i5 * 6;
                for (int i7 = 0; i7 < 3; i7++) {
                    long[] jArr2 = jArr;
                    create64[i7] = jArr2[i6 + i7];
                    create642[i7] = jArr2[3 + i6 + i7];
                }
                return createPoint(create64, create642);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecT131R2Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecT131R2Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecT131FieldElement(bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public int getFieldSize() {
        return 131;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    public int getK1() {
        return 2;
    }

    public int getK2() {
        return 3;
    }

    public int getK3() {
        return 8;
    }

    public int getM() {
        return 131;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractF2m
    public boolean isKoblitz() {
        return false;
    }

    public boolean isTrinomial() {
        return false;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        return i == 6;
    }
}