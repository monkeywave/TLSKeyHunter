package org.bouncycastle.math.p010ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p010ec.AbstractECLookupTable;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECLookupTable;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP384R1Curve */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP384R1Curve.class */
public class SecP384R1Curve extends ECCurve.AbstractFp {
    private static final int SECP384R1_DEFAULT_COORDS = 2;
    protected SecP384R1Point infinity;

    /* renamed from: q */
    public static final BigInteger f742q = SecP384R1FieldElement.f745Q;
    private static final ECFieldElement[] SECP384R1_AFFINE_ZS = {new SecP384R1FieldElement(ECConstants.ONE)};

    public SecP384R1Curve() {
        super(f742q);
        this.infinity = new SecP384R1Point(this, null, null);
        this.f661a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC")));
        this.f662b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973"));
        this.cofactor = BigInteger.valueOf(1L);
        this.coord = 2;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecP384R1Curve();
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
        return f742q;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public int getFieldSize() {
        return f742q.bitLength();
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecP384R1FieldElement(bigInteger);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecP384R1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecP384R1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int[] iArr = new int[i2 * 12 * 2];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat.copy(12, ((SecP384R1FieldElement) eCPoint.getRawXCoord()).f746x, 0, iArr, i3);
            int i5 = i3 + 12;
            Nat.copy(12, ((SecP384R1FieldElement) eCPoint.getRawYCoord()).f746x, 0, iArr, i5);
            i3 = i5 + 12;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecP384R1Curve.1
            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookup(int i6) {
                int[] create = Nat.create(12);
                int[] create2 = Nat.create(12);
                int i7 = 0;
                for (int i8 = 0; i8 < i2; i8++) {
                    int i9 = ((i8 ^ i6) - 1) >> 31;
                    for (int i10 = 0; i10 < 12; i10++) {
                        int i11 = i10;
                        create[i11] = create[i11] ^ (iArr[i7 + i10] & i9);
                        int i12 = i10;
                        create2[i12] = create2[i12] ^ (iArr[(i7 + 12) + i10] & i9);
                    }
                    i7 += 24;
                }
                return createPoint(create, create2);
            }

            @Override // org.bouncycastle.math.p010ec.AbstractECLookupTable, org.bouncycastle.math.p010ec.ECLookupTable
            public ECPoint lookupVar(int i6) {
                int[] create = Nat.create(12);
                int[] create2 = Nat.create(12);
                int i7 = i6 * 12 * 2;
                for (int i8 = 0; i8 < 12; i8++) {
                    create[i8] = iArr[i7 + i8];
                    create2[i8] = iArr[i7 + 12 + i8];
                }
                return createPoint(create, create2);
            }

            private ECPoint createPoint(int[] iArr2, int[] iArr3) {
                return SecP384R1Curve.this.createRawPoint(new SecP384R1FieldElement(iArr2), new SecP384R1FieldElement(iArr3), SecP384R1Curve.SECP384R1_AFFINE_ZS);
            }
        };
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractFp, org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
        int[] create = Nat.create(12);
        SecP384R1Field.random(secureRandom, create);
        return new SecP384R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p010ec.ECCurve.AbstractFp, org.bouncycastle.math.p010ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
        int[] create = Nat.create(12);
        SecP384R1Field.randomMult(secureRandom, create);
        return new SecP384R1FieldElement(create);
    }
}