package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.AbstractECLookupTable;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECLookupTable;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat224;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP224R1Curve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP224R1Curve.class */
public class SecP224R1Curve extends ECCurve.AbstractFp {
    private static final int SECP224R1_DEFAULT_COORDS = 2;
    protected SecP224R1Point infinity;

    /* renamed from: q */
    public static final BigInteger f725q = SecP224R1FieldElement.f729Q;
    private static final ECFieldElement[] SECP224R1_AFFINE_ZS = {new SecP224R1FieldElement(ECConstants.ONE)};

    public SecP224R1Curve() {
        super(f725q);
        this.infinity = new SecP224R1Point(this, null, null);
        this.f661a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE")));
        this.f662b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D"));
        this.cofactor = BigInteger.valueOf(1L);
        this.coord = 2;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecP224R1Curve();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        switch (i) {
            case 2:
                return true;
            default:
                return false;
        }
    }

    public BigInteger getQ() {
        return f725q;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public int getFieldSize() {
        return f725q.bitLength();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecP224R1FieldElement(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecP224R1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecP224R1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int[] iArr = new int[i2 * 7 * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat224.copy(((SecP224R1FieldElement) eCPoint.getRawXCoord()).f730x, 0, iArr, i3);
            int i5 = i3 + 7;
            Nat224.copy(((SecP224R1FieldElement) eCPoint.getRawYCoord()).f730x, 0, iArr, i5);
            i3 = i5 + 7;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecP224R1Curve.1
            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookup(int i6) {
                int[] create = Nat224.create();
                int[] create2 = Nat224.create();
                int i7 = 0;
                for (int i8 = 0; i8 < i2; i8++) {
                    int i9 = ((i8 ^ i6) - 1) >> 31;
                    for (int i10 = 0; i10 < 7; i10++) {
                        int i11 = i10;
                        create[i11] = create[i11] ^ (iArr[i7 + i10] & i9);
                        int i12 = i10;
                        create2[i12] = create2[i12] ^ (iArr[(i7 + 7) + i10] & i9);
                    }
                    i7 += 14;
                }
                return createPoint(create, create2);
            }

            @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookupVar(int i6) {
                int[] create = Nat224.create();
                int[] create2 = Nat224.create();
                int i7 = i6 * 7 * 2;
                for (int i8 = 0; i8 < 7; i8++) {
                    create[i8] = iArr[i7 + i8];
                    create2[i8] = iArr[i7 + 7 + i8];
                }
                return createPoint(create, create2);
            }

            private ECPoint createPoint(int[] iArr2, int[] iArr3) {
                return SecP224R1Curve.this.createRawPoint(new SecP224R1FieldElement(iArr2), new SecP224R1FieldElement(iArr3), SecP224R1Curve.SECP224R1_AFFINE_ZS);
            }
        };
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractFp, org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
        int[] create = Nat224.create();
        SecP224R1Field.random(secureRandom, create);
        return new SecP224R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractFp, org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
        int[] create = Nat224.create();
        SecP224R1Field.randomMult(secureRandom, create);
        return new SecP224R1FieldElement(create);
    }
}