package org.bouncycastle.math.p016ec.custom.djb;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.math.p016ec.AbstractECLookupTable;
import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECLookupTable;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;
import org.bouncycastle.util.encoders.Hex;

/* renamed from: org.bouncycastle.math.ec.custom.djb.Curve25519 */
/* loaded from: classes2.dex */
public class Curve25519 extends ECCurve.AbstractFp {
    private static final ECFieldElement[] CURVE25519_AFFINE_ZS;
    private static final int CURVE25519_DEFAULT_COORDS = 4;
    private static final BigInteger C_a;
    private static final BigInteger C_b;

    /* renamed from: q */
    public static final BigInteger f1020q = Curve25519FieldElement.f1024Q;
    protected Curve25519Point infinity;

    static {
        BigInteger bigInteger = new BigInteger(1, Hex.decodeStrict("2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA984914A144"));
        C_a = bigInteger;
        C_b = new BigInteger(1, Hex.decodeStrict("7B425ED097B425ED097B425ED097B425ED097B425ED097B4260B5E9C7710C864"));
        CURVE25519_AFFINE_ZS = new ECFieldElement[]{new Curve25519FieldElement(ECConstants.ONE), new Curve25519FieldElement(bigInteger)};
    }

    public Curve25519() {
        super(f1020q);
        this.infinity = new Curve25519Point(this, null, null);
        this.f1000a = fromBigInteger(C_a);
        this.f1001b = fromBigInteger(C_b);
        this.order = new BigInteger(1, Hex.decodeStrict("1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED"));
        this.cofactor = BigInteger.valueOf(8L);
        this.coord = 4;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    protected ECCurve cloneCurve() {
        return new Curve25519();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECLookupTable createCacheSafeLookupTable(ECPoint[] eCPointArr, int i, final int i2) {
        final int[] iArr = new int[i2 * 16];
        int i3 = 0;
        for (int i4 = 0; i4 < i2; i4++) {
            ECPoint eCPoint = eCPointArr[i + i4];
            Nat256.copy(((Curve25519FieldElement) eCPoint.getRawXCoord()).f1025x, 0, iArr, i3);
            Nat256.copy(((Curve25519FieldElement) eCPoint.getRawYCoord()).f1025x, 0, iArr, i3 + 8);
            i3 += 16;
        }
        return new AbstractECLookupTable() { // from class: org.bouncycastle.math.ec.custom.djb.Curve25519.1
            private ECPoint createPoint(int[] iArr2, int[] iArr3) {
                return Curve25519.this.createRawPoint(new Curve25519FieldElement(iArr2), new Curve25519FieldElement(iArr3), Curve25519.CURVE25519_AFFINE_ZS);
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public int getSize() {
                return i2;
            }

            @Override // org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookup(int i5) {
                int[] create = Nat256.create();
                int[] create2 = Nat256.create();
                int i6 = 0;
                for (int i7 = 0; i7 < i2; i7++) {
                    int i8 = ((i7 ^ i5) - 1) >> 31;
                    for (int i9 = 0; i9 < 8; i9++) {
                        int i10 = create[i9];
                        int[] iArr2 = iArr;
                        create[i9] = i10 ^ (iArr2[i6 + i9] & i8);
                        create2[i9] = create2[i9] ^ (iArr2[(i6 + 8) + i9] & i8);
                    }
                    i6 += 16;
                }
                return createPoint(create, create2);
            }

            @Override // org.bouncycastle.math.p016ec.AbstractECLookupTable, org.bouncycastle.math.p016ec.ECLookupTable
            public ECPoint lookupVar(int i5) {
                int[] create = Nat256.create();
                int[] create2 = Nat256.create();
                int i6 = i5 * 16;
                for (int i7 = 0; i7 < 8; i7++) {
                    int[] iArr2 = iArr;
                    create[i7] = iArr2[i6 + i7];
                    create2[i7] = iArr2[8 + i6 + i7];
                }
                return createPoint(create, create2);
            }
        };
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return new Curve25519Point(this, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint createRawPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        return new Curve25519Point(this, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement fromBigInteger(BigInteger bigInteger) {
        return new Curve25519FieldElement(bigInteger);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public int getFieldSize() {
        return f1020q.bitLength();
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public ECPoint getInfinity() {
        return this.infinity;
    }

    public BigInteger getQ() {
        return f1020q;
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElement(SecureRandom secureRandom) {
        int[] create = Nat256.create();
        Curve25519Field.random(secureRandom, create);
        return new Curve25519FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve.AbstractFp, org.bouncycastle.math.p016ec.ECCurve
    public ECFieldElement randomFieldElementMult(SecureRandom secureRandom) {
        int[] create = Nat256.create();
        Curve25519Field.randomMult(secureRandom, create);
        return new Curve25519FieldElement(create);
    }

    @Override // org.bouncycastle.math.p016ec.ECCurve
    public boolean supportsCoordinateSystem(int i) {
        return i == 4;
    }
}