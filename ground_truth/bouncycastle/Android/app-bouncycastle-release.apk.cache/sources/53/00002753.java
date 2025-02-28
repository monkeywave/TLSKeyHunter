package org.bouncycastle.math.p016ec.custom.sec;

import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256K1Point */
/* loaded from: classes2.dex */
public class SecP256K1Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP256K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP256K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint add(ECPoint eCPoint) {
        int[] iArr;
        int[] iArr2;
        int[] iArr3;
        int[] iArr4;
        if (isInfinity()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return this;
        }
        if (this == eCPoint) {
            return twice();
        }
        ECCurve curve = getCurve();
        SecP256K1FieldElement secP256K1FieldElement = (SecP256K1FieldElement) this.f1015x;
        SecP256K1FieldElement secP256K1FieldElement2 = (SecP256K1FieldElement) this.f1016y;
        SecP256K1FieldElement secP256K1FieldElement3 = (SecP256K1FieldElement) eCPoint.getXCoord();
        SecP256K1FieldElement secP256K1FieldElement4 = (SecP256K1FieldElement) eCPoint.getYCoord();
        SecP256K1FieldElement secP256K1FieldElement5 = (SecP256K1FieldElement) this.f1017zs[0];
        SecP256K1FieldElement secP256K1FieldElement6 = (SecP256K1FieldElement) eCPoint.getZCoord(0);
        int[] createExt = Nat256.createExt();
        int[] createExt2 = Nat256.createExt();
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        boolean isOne = secP256K1FieldElement5.isOne();
        if (isOne) {
            iArr = secP256K1FieldElement3.f1074x;
            iArr2 = secP256K1FieldElement4.f1074x;
        } else {
            SecP256K1Field.square(secP256K1FieldElement5.f1074x, create2, createExt);
            SecP256K1Field.multiply(create2, secP256K1FieldElement3.f1074x, create, createExt);
            SecP256K1Field.multiply(create2, secP256K1FieldElement5.f1074x, create2, createExt);
            SecP256K1Field.multiply(create2, secP256K1FieldElement4.f1074x, create2, createExt);
            iArr = create;
            iArr2 = create2;
        }
        boolean isOne2 = secP256K1FieldElement6.isOne();
        if (isOne2) {
            iArr3 = secP256K1FieldElement.f1074x;
            iArr4 = secP256K1FieldElement2.f1074x;
        } else {
            SecP256K1Field.square(secP256K1FieldElement6.f1074x, create3, createExt);
            SecP256K1Field.multiply(create3, secP256K1FieldElement.f1074x, createExt2, createExt);
            SecP256K1Field.multiply(create3, secP256K1FieldElement6.f1074x, create3, createExt);
            SecP256K1Field.multiply(create3, secP256K1FieldElement2.f1074x, create3, createExt);
            iArr3 = createExt2;
            iArr4 = create3;
        }
        int[] create4 = Nat256.create();
        SecP256K1Field.subtract(iArr3, iArr, create4);
        SecP256K1Field.subtract(iArr4, iArr2, create);
        if (Nat256.isZero(create4)) {
            return Nat256.isZero(create) ? twice() : curve.getInfinity();
        }
        SecP256K1Field.square(create4, create2, createExt);
        int[] create5 = Nat256.create();
        SecP256K1Field.multiply(create2, create4, create5, createExt);
        SecP256K1Field.multiply(create2, iArr3, create2, createExt);
        SecP256K1Field.negate(create5, create5);
        Nat256.mul(iArr4, create5, createExt2);
        SecP256K1Field.reduce32(Nat256.addBothTo(create2, create2, create5), create5);
        SecP256K1FieldElement secP256K1FieldElement7 = new SecP256K1FieldElement(create3);
        SecP256K1Field.square(create, secP256K1FieldElement7.f1074x, createExt);
        SecP256K1Field.subtract(secP256K1FieldElement7.f1074x, create5, secP256K1FieldElement7.f1074x);
        SecP256K1FieldElement secP256K1FieldElement8 = new SecP256K1FieldElement(create5);
        SecP256K1Field.subtract(create2, secP256K1FieldElement7.f1074x, secP256K1FieldElement8.f1074x);
        SecP256K1Field.multiplyAddToExt(secP256K1FieldElement8.f1074x, create, createExt2);
        SecP256K1Field.reduce(createExt2, secP256K1FieldElement8.f1074x);
        SecP256K1FieldElement secP256K1FieldElement9 = new SecP256K1FieldElement(create4);
        if (!isOne) {
            SecP256K1Field.multiply(secP256K1FieldElement9.f1074x, secP256K1FieldElement5.f1074x, secP256K1FieldElement9.f1074x, createExt);
        }
        if (!isOne2) {
            SecP256K1Field.multiply(secP256K1FieldElement9.f1074x, secP256K1FieldElement6.f1074x, secP256K1FieldElement9.f1074x, createExt);
        }
        return new SecP256K1Point(curve, secP256K1FieldElement7, secP256K1FieldElement8, new ECFieldElement[]{secP256K1FieldElement9});
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    protected ECPoint detach() {
        return new SecP256K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new SecP256K1Point(this.curve, this.f1015x, this.f1016y.negate(), this.f1017zs);
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint threeTimes() {
        return (isInfinity() || this.f1016y.isZero()) ? this : twice().add(this);
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecP256K1FieldElement secP256K1FieldElement = (SecP256K1FieldElement) this.f1016y;
        if (secP256K1FieldElement.isZero()) {
            return curve.getInfinity();
        }
        SecP256K1FieldElement secP256K1FieldElement2 = (SecP256K1FieldElement) this.f1015x;
        SecP256K1FieldElement secP256K1FieldElement3 = (SecP256K1FieldElement) this.f1017zs[0];
        int[] createExt = Nat256.createExt();
        int[] create = Nat256.create();
        SecP256K1Field.square(secP256K1FieldElement.f1074x, create, createExt);
        int[] create2 = Nat256.create();
        SecP256K1Field.square(create, create2, createExt);
        int[] create3 = Nat256.create();
        SecP256K1Field.square(secP256K1FieldElement2.f1074x, create3, createExt);
        SecP256K1Field.reduce32(Nat256.addBothTo(create3, create3, create3), create3);
        SecP256K1Field.multiply(create, secP256K1FieldElement2.f1074x, create, createExt);
        SecP256K1Field.reduce32(Nat.shiftUpBits(8, create, 2, 0), create);
        int[] create4 = Nat256.create();
        SecP256K1Field.reduce32(Nat.shiftUpBits(8, create2, 3, 0, create4), create4);
        SecP256K1FieldElement secP256K1FieldElement4 = new SecP256K1FieldElement(create2);
        SecP256K1Field.square(create3, secP256K1FieldElement4.f1074x, createExt);
        SecP256K1Field.subtract(secP256K1FieldElement4.f1074x, create, secP256K1FieldElement4.f1074x);
        SecP256K1Field.subtract(secP256K1FieldElement4.f1074x, create, secP256K1FieldElement4.f1074x);
        SecP256K1FieldElement secP256K1FieldElement5 = new SecP256K1FieldElement(create);
        SecP256K1Field.subtract(create, secP256K1FieldElement4.f1074x, secP256K1FieldElement5.f1074x);
        SecP256K1Field.multiply(secP256K1FieldElement5.f1074x, create3, secP256K1FieldElement5.f1074x, createExt);
        SecP256K1Field.subtract(secP256K1FieldElement5.f1074x, create4, secP256K1FieldElement5.f1074x);
        SecP256K1FieldElement secP256K1FieldElement6 = new SecP256K1FieldElement(create3);
        SecP256K1Field.twice(secP256K1FieldElement.f1074x, secP256K1FieldElement6.f1074x);
        if (!secP256K1FieldElement3.isOne()) {
            SecP256K1Field.multiply(secP256K1FieldElement6.f1074x, secP256K1FieldElement3.f1074x, secP256K1FieldElement6.f1074x, createExt);
        }
        return new SecP256K1Point(curve, secP256K1FieldElement4, secP256K1FieldElement5, new ECFieldElement[]{secP256K1FieldElement6});
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        return this == eCPoint ? threeTimes() : isInfinity() ? eCPoint : eCPoint.isInfinity() ? twice() : this.f1016y.isZero() ? eCPoint : twice().add(eCPoint);
    }
}