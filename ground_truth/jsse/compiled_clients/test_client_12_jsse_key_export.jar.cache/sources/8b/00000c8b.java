package org.bouncycastle.math.p010ec.custom.sec;

import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat224;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP224R1Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP224R1Point.class */
public class SecP224R1Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP224R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP224R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new SecP224R1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
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
        SecP224R1FieldElement secP224R1FieldElement = (SecP224R1FieldElement) this.f676x;
        SecP224R1FieldElement secP224R1FieldElement2 = (SecP224R1FieldElement) this.f677y;
        SecP224R1FieldElement secP224R1FieldElement3 = (SecP224R1FieldElement) eCPoint.getXCoord();
        SecP224R1FieldElement secP224R1FieldElement4 = (SecP224R1FieldElement) eCPoint.getYCoord();
        SecP224R1FieldElement secP224R1FieldElement5 = (SecP224R1FieldElement) this.f678zs[0];
        SecP224R1FieldElement secP224R1FieldElement6 = (SecP224R1FieldElement) eCPoint.getZCoord(0);
        int[] createExt = Nat224.createExt();
        int[] create = Nat224.create();
        int[] create2 = Nat224.create();
        int[] create3 = Nat224.create();
        boolean isOne = secP224R1FieldElement5.isOne();
        if (isOne) {
            iArr2 = secP224R1FieldElement3.f730x;
            iArr = secP224R1FieldElement4.f730x;
        } else {
            iArr = create2;
            SecP224R1Field.square(secP224R1FieldElement5.f730x, iArr);
            iArr2 = create;
            SecP224R1Field.multiply(iArr, secP224R1FieldElement3.f730x, iArr2);
            SecP224R1Field.multiply(iArr, secP224R1FieldElement5.f730x, iArr);
            SecP224R1Field.multiply(iArr, secP224R1FieldElement4.f730x, iArr);
        }
        boolean isOne2 = secP224R1FieldElement6.isOne();
        if (isOne2) {
            iArr4 = secP224R1FieldElement.f730x;
            iArr3 = secP224R1FieldElement2.f730x;
        } else {
            iArr3 = create3;
            SecP224R1Field.square(secP224R1FieldElement6.f730x, iArr3);
            iArr4 = createExt;
            SecP224R1Field.multiply(iArr3, secP224R1FieldElement.f730x, iArr4);
            SecP224R1Field.multiply(iArr3, secP224R1FieldElement6.f730x, iArr3);
            SecP224R1Field.multiply(iArr3, secP224R1FieldElement2.f730x, iArr3);
        }
        int[] create4 = Nat224.create();
        SecP224R1Field.subtract(iArr4, iArr2, create4);
        SecP224R1Field.subtract(iArr3, iArr, create);
        if (Nat224.isZero(create4)) {
            return Nat224.isZero(create) ? twice() : curve.getInfinity();
        }
        SecP224R1Field.square(create4, create2);
        int[] create5 = Nat224.create();
        SecP224R1Field.multiply(create2, create4, create5);
        SecP224R1Field.multiply(create2, iArr4, create2);
        SecP224R1Field.negate(create5, create5);
        Nat224.mul(iArr3, create5, createExt);
        SecP224R1Field.reduce32(Nat224.addBothTo(create2, create2, create5), create5);
        SecP224R1FieldElement secP224R1FieldElement7 = new SecP224R1FieldElement(create3);
        SecP224R1Field.square(create, secP224R1FieldElement7.f730x);
        SecP224R1Field.subtract(secP224R1FieldElement7.f730x, create5, secP224R1FieldElement7.f730x);
        SecP224R1FieldElement secP224R1FieldElement8 = new SecP224R1FieldElement(create5);
        SecP224R1Field.subtract(create2, secP224R1FieldElement7.f730x, secP224R1FieldElement8.f730x);
        SecP224R1Field.multiplyAddToExt(secP224R1FieldElement8.f730x, create, createExt);
        SecP224R1Field.reduce(createExt, secP224R1FieldElement8.f730x);
        SecP224R1FieldElement secP224R1FieldElement9 = new SecP224R1FieldElement(create4);
        if (!isOne) {
            SecP224R1Field.multiply(secP224R1FieldElement9.f730x, secP224R1FieldElement5.f730x, secP224R1FieldElement9.f730x);
        }
        if (!isOne2) {
            SecP224R1Field.multiply(secP224R1FieldElement9.f730x, secP224R1FieldElement6.f730x, secP224R1FieldElement9.f730x);
        }
        return new SecP224R1Point(curve, secP224R1FieldElement7, secP224R1FieldElement8, new ECFieldElement[]{secP224R1FieldElement9});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecP224R1FieldElement secP224R1FieldElement = (SecP224R1FieldElement) this.f677y;
        if (secP224R1FieldElement.isZero()) {
            return curve.getInfinity();
        }
        SecP224R1FieldElement secP224R1FieldElement2 = (SecP224R1FieldElement) this.f676x;
        SecP224R1FieldElement secP224R1FieldElement3 = (SecP224R1FieldElement) this.f678zs[0];
        int[] create = Nat224.create();
        int[] create2 = Nat224.create();
        int[] create3 = Nat224.create();
        SecP224R1Field.square(secP224R1FieldElement.f730x, create3);
        int[] create4 = Nat224.create();
        SecP224R1Field.square(create3, create4);
        boolean isOne = secP224R1FieldElement3.isOne();
        int[] iArr = secP224R1FieldElement3.f730x;
        if (!isOne) {
            iArr = create2;
            SecP224R1Field.square(secP224R1FieldElement3.f730x, iArr);
        }
        SecP224R1Field.subtract(secP224R1FieldElement2.f730x, iArr, create);
        SecP224R1Field.add(secP224R1FieldElement2.f730x, iArr, create2);
        SecP224R1Field.multiply(create2, create, create2);
        SecP224R1Field.reduce32(Nat224.addBothTo(create2, create2, create2), create2);
        SecP224R1Field.multiply(create3, secP224R1FieldElement2.f730x, create3);
        SecP224R1Field.reduce32(Nat.shiftUpBits(7, create3, 2, 0), create3);
        SecP224R1Field.reduce32(Nat.shiftUpBits(7, create4, 3, 0, create), create);
        SecP224R1FieldElement secP224R1FieldElement4 = new SecP224R1FieldElement(create4);
        SecP224R1Field.square(create2, secP224R1FieldElement4.f730x);
        SecP224R1Field.subtract(secP224R1FieldElement4.f730x, create3, secP224R1FieldElement4.f730x);
        SecP224R1Field.subtract(secP224R1FieldElement4.f730x, create3, secP224R1FieldElement4.f730x);
        SecP224R1FieldElement secP224R1FieldElement5 = new SecP224R1FieldElement(create3);
        SecP224R1Field.subtract(create3, secP224R1FieldElement4.f730x, secP224R1FieldElement5.f730x);
        SecP224R1Field.multiply(secP224R1FieldElement5.f730x, create2, secP224R1FieldElement5.f730x);
        SecP224R1Field.subtract(secP224R1FieldElement5.f730x, create, secP224R1FieldElement5.f730x);
        SecP224R1FieldElement secP224R1FieldElement6 = new SecP224R1FieldElement(create2);
        SecP224R1Field.twice(secP224R1FieldElement.f730x, secP224R1FieldElement6.f730x);
        if (!isOne) {
            SecP224R1Field.multiply(secP224R1FieldElement6.f730x, secP224R1FieldElement3.f730x, secP224R1FieldElement6.f730x);
        }
        return new SecP224R1Point(curve, secP224R1FieldElement4, secP224R1FieldElement5, new ECFieldElement[]{secP224R1FieldElement6});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        return this == eCPoint ? threeTimes() : isInfinity() ? eCPoint : eCPoint.isInfinity() ? twice() : this.f677y.isZero() ? eCPoint : twice().add(eCPoint);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint threeTimes() {
        return (isInfinity() || this.f677y.isZero()) ? this : twice().add(this);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new SecP224R1Point(this.curve, this.f676x, this.f677y.negate(), this.f678zs);
    }
}