package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p010ec.AbstractECLookupTable;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECLookupTable;
import org.bouncycastle.math.p010ec.ECMultiplier;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.WTauNafMultiplier;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT233K1Curve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT233K1Curve.class */
public class SecT233K1Curve extends ECCurve.AbstractF2m {
    private static final int SECT233K1_DEFAULT_COORDS = 6;
    private static final ECFieldElement[] SECT233K1_AFFINE_ZS = {new SecT233FieldElement(ECConstants.ONE)};
    protected SecT233K1Point infinity;

    public SecT233K1Curve() {
        super(233, 74, 0, 0);
        this.infinity = new SecT233K1Point(this, null, null);
        this.f661a = fromBigInteger(BigInteger.valueOf(0L));
        this.f662b = fromBigInteger(BigInteger.valueOf(1L));
        this.order = new BigInteger(1, Hex.decodeStrict("8000000000000000000000000000069D5BB915BCD46EFB1AD5F173ABDF"));
        this.cofactor = BigInteger.valueOf(4L);
        this.coord = 6;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecT233K1Curve();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        switch (i) {
            case 6:
                return true;
            default:
                return false;
        }
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    protected ECMultiplier createDefaultMultiplier() {
        return new WTauNafMultiplier();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public int getFieldSize() {
        return 233;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecT233FieldElement(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecT233K1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecT233K1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractF2m
    public boolean isKoblitz() {
        return true;
    }

    public int getM() {
        return 233;
    }

    public boolean isTrinomial() {
        return true;
    }

    public int getK1() {
        return 74;
    }

    public int getK2() {
        return 0;
    }

    public int getK3() {
        return 0;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final long[] jArr = new long[i2 * 4 * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat256.copy64(((SecT233FieldElement) eCPoint.getRawXCoord()).f755x, 0, jArr, i3);
            int i5 = i3 + 4;
            Nat256.copy64(((SecT233FieldElement) eCPoint.getRawYCoord()).f755x, 0, jArr, i5);
            i3 = i5 + 4;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecT233K1Curve.1
            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookup(int i6) {
                long[] create64 = Nat256.create64();
                long[] create642 = Nat256.create64();
                int i7 = 0;
                for (int i8 = 0; i8 < i2; i8++) {
                    long j = ((i8 ^ i6) - 1) >> 31;
                    for (int i9 = 0; i9 < 4; i9++) {
                        int i10 = i9;
                        create64[i10] = create64[i10] ^ (jArr[i7 + i9] & j);
                        int i11 = i9;
                        create642[i11] = create642[i11] ^ (jArr[(i7 + 4) + i9] & j);
                    }
                    i7 += 8;
                }
                return createPoint(create64, create642);
            }

            @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookupVar(int i6) {
                long[] create64 = Nat256.create64();
                long[] create642 = Nat256.create64();
                int i7 = i6 * 4 * 2;
                for (int i8 = 0; i8 < 4; i8++) {
                    create64[i8] = jArr[i7 + i8];
                    create642[i8] = jArr[i7 + 4 + i8];
                }
                return createPoint(create64, create642);
            }

            private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                return SecT233K1Curve.this.createRawPoint(new SecT233FieldElement(jArr2), new SecT233FieldElement(jArr3), SecT233K1Curve.SECT233K1_AFFINE_ZS);
            }
        };
    }
}