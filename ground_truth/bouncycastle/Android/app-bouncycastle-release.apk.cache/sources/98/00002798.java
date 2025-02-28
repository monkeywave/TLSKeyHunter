package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import org.bouncycastle.math.p016ec.AbstractECLookupTable;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECLookupTable;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat320;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT283R1Curve */
/* loaded from: classes2.dex */
public class SecT283R1Curve extends ECCurve.AbstractF2m {
    private static final ECFieldElement[] SECT283R1_AFFINE_ZS = {new SecT283FieldElement(ECConstants.ONE)};
    private static final int SECT283R1_DEFAULT_COORDS = 6;
    protected SecT283R1Point infinity;

    public SecT283R1Curve() {
        super(283, 5, 7, 12);
        this.infinity = new SecT283R1Point(this, null, null);
        this.f1000a = fromBigInteger(BigInteger.valueOf(1L));
        this.f1001b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("027B680AC8B8596DA5A4AF8A19A0303FCA97FD7645309FA2A581485AF6263E313B79A2F5")));
        this.order = new BigInteger(1, Hex.decodeStrict("03FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEF90399660FC938A90165B042A7CEFADB307"));
        this.cofactor = BigInteger.valueOf(2L);
        this.coord = 6;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecT283R1Curve();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final long[] jArr = new long[i2 * 10];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat320.copy64(((SecT283FieldElement) eCPoint.getRawXCoord()).f1096x, 0, jArr, i3);
            Nat320.copy64(((SecT283FieldElement) eCPoint.getRawYCoord()).f1096x, 0, jArr, i3 + 5);
            i3 += 10;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecT283R1Curve.1
            private ECPoint createPoint(long[] jArr2, long[] jArr3) {
                return SecT283R1Curve.this.createRawPoint(new SecT283FieldElement(jArr2), new SecT283FieldElement(jArr3), SecT283R1Curve.SECT283R1_AFFINE_ZS);
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i5) {
                long[] create64 = Nat320.create64();
                long[] create642 = Nat320.create64();
                int i6 = 0;
                for (int i7 = 0; i7 < i2; i7++) {
                    long j = ((i7 ^ i5) - 1) >> 31;
                    for (int i8 = 0; i8 < 5; i8++) {
                        long j2 = create64[i8];
                        long[] jArr2 = jArr;
                        create64[i8] = j2 ^ (jArr2[i6 + i8] & j);
                        create642[i8] = create642[i8] ^ (jArr2[(i6 + 5) + i8] & j);
                    }
                    i6 += 10;
                }
                return createPoint(create64, create642);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i5) {
                long[] create64 = Nat320.create64();
                long[] create642 = Nat320.create64();
                int i6 = i5 * 10;
                for (int i7 = 0; i7 < 5; i7++) {
                    long[] jArr2 = jArr;
                    create64[i7] = jArr2[i6 + i7];
                    create642[i7] = jArr2[5 + i6 + i7];
                }
                return createPoint(create64, create642);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecT283R1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecT283R1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecT283FieldElement(bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public int getFieldSize() {
        return 283;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    public int getK1() {
        return 5;
    }

    public int getK2() {
        return 7;
    }

    public int getK3() {
        return 12;
    }

    public int getM() {
        return 283;
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