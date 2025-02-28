package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p016ec.AbstractECLookupTable;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECLookupTable;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat192;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP192K1Curve */
/* loaded from: classes2.dex */
public class SecP192K1Curve extends ECCurve.AbstractFp {
    private static final int SECP192K1_DEFAULT_COORDS = 2;
    protected SecP192K1Point infinity;

    /* renamed from: q */
    public static final BigInteger f1048q = SecP192K1FieldElement.f1051Q;
    private static final ECFieldElement[] SECP192K1_AFFINE_ZS = {new SecP192K1FieldElement(ECConstants.ONE)};

    public SecP192K1Curve() {
        super(f1048q);
        this.infinity = new SecP192K1Point(this, null, null);
        this.f1000a = fromBigInteger(ECConstants.ZERO);
        this.f1001b = fromBigInteger(BigInteger.valueOf(3L));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D"));
        this.cofactor = BigInteger.valueOf(1L);
        this.coord = 2;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecP192K1Curve();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int[] iArr = new int[i2 * 12];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat192.copy(((SecP192K1FieldElement) eCPoint.getRawXCoord()).f1052x, 0, iArr, i3);
            Nat192.copy(((SecP192K1FieldElement) eCPoint.getRawYCoord()).f1052x, 0, iArr, i3 + 6);
            i3 += 12;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecP192K1Curve.1
            private ECPoint createPoint(int[] iArr2, int[] iArr3) {
                return SecP192K1Curve.this.createRawPoint(new SecP192K1FieldElement(iArr2), new SecP192K1FieldElement(iArr3), SecP192K1Curve.SECP192K1_AFFINE_ZS);
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i5) {
                int[] create = Nat192.create();
                int[] create2 = Nat192.create();
                int i6 = 0;
                for (int i7 = 0; i7 < i2; i7++) {
                    int i8 = ((i7 ^ i5) - 1) >> 31;
                    for (int i9 = 0; i9 < 6; i9++) {
                        int i10 = create[i9];
                        int[] iArr2 = iArr;
                        create[i9] = i10 ^ (iArr2[i6 + i9] & i8);
                        create2[i9] = create2[i9] ^ (iArr2[(i6 + 6) + i9] & i8);
                    }
                    i6 += 12;
                }
                return createPoint(create, create2);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i5) {
                int[] create = Nat192.create();
                int[] create2 = Nat192.create();
                int i6 = i5 * 12;
                for (int i7 = 0; i7 < 6; i7++) {
                    int[] iArr2 = iArr;
                    create[i7] = iArr2[i6 + i7];
                    create2[i7] = iArr2[6 + i6 + i7];
                }
                return createPoint(create, create2);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecP192K1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecP192K1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecP192K1FieldElement(bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public int getFieldSize() {
        return f1048q.bitLength();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    public BigInteger getQ() {
        return f1048q;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
        int[] create = Nat192.create();
        SecP192K1Field.random(secureRandom, create);
        return new SecP192K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
        int[] create = Nat192.create();
        SecP192K1Field.randomMult(secureRandom, create);
        return new SecP192K1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        return i == 2;
    }
}