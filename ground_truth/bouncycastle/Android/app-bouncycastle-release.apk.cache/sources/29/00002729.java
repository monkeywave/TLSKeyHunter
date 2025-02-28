package org.bouncycastle.math.p016ec.custom.sec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p016ec.AbstractECLookupTable;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECLookupTable;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat128;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP128R1Curve */
/* loaded from: classes2.dex */
public class SecP128R1Curve extends ECCurve.AbstractFp {
    private static final int SECP128R1_DEFAULT_COORDS = 2;
    protected SecP128R1Point infinity;

    /* renamed from: q */
    public static final BigInteger f1031q = SecP128R1FieldElement.f1034Q;
    private static final ECFieldElement[] SECP128R1_AFFINE_ZS = {new SecP128R1FieldElement(ECConstants.ONE)};

    public SecP128R1Curve() {
        super(f1031q);
        this.infinity = new SecP128R1Point(this, null, null);
        this.f1000a = fromBigInteger(new BigInteger(1, Hex.decodeStrict("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC")));
        this.f1001b = fromBigInteger(new BigInteger(1, Hex.decodeStrict("E87579C11079F43DD824993C2CEE5ED3")));
        this.order = new BigInteger(1, Hex.decodeStrict("FFFFFFFE0000000075A30D1B9038A115"));
        this.cofactor = BigInteger.valueOf(1L);
        this.coord = 2;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    protected ECCurve cloneCurve() {
        return new SecP128R1Curve();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int[] iArr = new int[i2 * 8];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat128.copy(((SecP128R1FieldElement) eCPoint.getRawXCoord()).f1035x, 0, iArr, i3);
            Nat128.copy(((SecP128R1FieldElement) eCPoint.getRawYCoord()).f1035x, 0, iArr, i3 + 4);
            i3 += 8;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.sec.SecP128R1Curve.1
            private ECPoint createPoint(int[] iArr2, int[] iArr3) {
                return SecP128R1Curve.this.createRawPoint(new SecP128R1FieldElement(iArr2), new SecP128R1FieldElement(iArr3), SecP128R1Curve.SECP128R1_AFFINE_ZS);
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i5) {
                int[] create = Nat128.create();
                int[] create2 = Nat128.create();
                int i6 = 0;
                for (int i7 = 0; i7 < i2; i7++) {
                    int i8 = ((i7 ^ i5) - 1) >> 31;
                    for (int i9 = 0; i9 < 4; i9++) {
                        int i10 = create[i9];
                        int[] iArr2 = iArr;
                        create[i9] = i10 ^ (iArr2[i6 + i9] & i8);
                        create2[i9] = create2[i9] ^ (iArr2[(i6 + 4) + i9] & i8);
                    }
                    i6 += 8;
                }
                return createPoint(create, create2);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i5) {
                int[] create = Nat128.create();
                int[] create2 = Nat128.create();
                int i6 = i5 * 8;
                for (int i7 = 0; i7 < 4; i7++) {
                    int[] iArr2 = iArr;
                    create[i7] = iArr2[i6 + i7];
                    create2[i7] = iArr2[4 + i6 + i7];
                }
                return createPoint(create, create2);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new SecP128R1Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new SecP128R1Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new SecP128R1FieldElement(bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public int getFieldSize() {
        return f1031q.bitLength();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    public BigInteger getQ() {
        return f1031q;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
        int[] create = Nat128.create();
        SecP128R1Field.random(secureRandom, create);
        return new SecP128R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
        int[] create = Nat128.create();
        SecP128R1Field.randomMult(secureRandom, create);
        return new SecP128R1FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        return i == 2;
    }
}