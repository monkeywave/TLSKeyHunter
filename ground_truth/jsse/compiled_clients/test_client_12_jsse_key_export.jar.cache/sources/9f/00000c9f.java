package org.bouncycastle.math.p010ec.custom.sec;

import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP521R1Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP521R1Point.class */
public class SecP521R1Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP521R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP521R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new SecP521R1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SecP521R1FieldElement secP521R1FieldElement = (SecP521R1FieldElement) this.f676x;
        SecP521R1FieldElement secP521R1FieldElement2 = (SecP521R1FieldElement) this.f677y;
        SecP521R1FieldElement secP521R1FieldElement3 = (SecP521R1FieldElement) eCPoint.getXCoord();
        SecP521R1FieldElement secP521R1FieldElement4 = (SecP521R1FieldElement) eCPoint.getYCoord();
        SecP521R1FieldElement secP521R1FieldElement5 = (SecP521R1FieldElement) this.f678zs[0];
        SecP521R1FieldElement secP521R1FieldElement6 = (SecP521R1FieldElement) eCPoint.getZCoord(0);
        int[] create = Nat.create(17);
        int[] create2 = Nat.create(17);
        int[] create3 = Nat.create(17);
        int[] create4 = Nat.create(17);
        boolean isOne = secP521R1FieldElement5.isOne();
        if (isOne) {
            iArr2 = secP521R1FieldElement3.f750x;
            iArr = secP521R1FieldElement4.f750x;
        } else {
            iArr = create3;
            SecP521R1Field.square(secP521R1FieldElement5.f750x, iArr);
            iArr2 = create2;
            SecP521R1Field.multiply(iArr, secP521R1FieldElement3.f750x, iArr2);
            SecP521R1Field.multiply(iArr, secP521R1FieldElement5.f750x, iArr);
            SecP521R1Field.multiply(iArr, secP521R1FieldElement4.f750x, iArr);
        }
        boolean isOne2 = secP521R1FieldElement6.isOne();
        if (isOne2) {
            iArr4 = secP521R1FieldElement.f750x;
            iArr3 = secP521R1FieldElement2.f750x;
        } else {
            iArr3 = create4;
            SecP521R1Field.square(secP521R1FieldElement6.f750x, iArr3);
            iArr4 = create;
            SecP521R1Field.multiply(iArr3, secP521R1FieldElement.f750x, iArr4);
            SecP521R1Field.multiply(iArr3, secP521R1FieldElement6.f750x, iArr3);
            SecP521R1Field.multiply(iArr3, secP521R1FieldElement2.f750x, iArr3);
        }
        int[] create5 = Nat.create(17);
        SecP521R1Field.subtract(iArr4, iArr2, create5);
        SecP521R1Field.subtract(iArr3, iArr, create2);
        if (Nat.isZero(17, create5)) {
            return Nat.isZero(17, create2) ? twice() : curve.getInfinity();
        }
        SecP521R1Field.square(create5, create3);
        int[] create6 = Nat.create(17);
        SecP521R1Field.multiply(create3, create5, create6);
        SecP521R1Field.multiply(create3, iArr4, create3);
        SecP521R1Field.multiply(iArr3, create6, create);
        SecP521R1FieldElement secP521R1FieldElement7 = new SecP521R1FieldElement(create4);
        SecP521R1Field.square(create2, secP521R1FieldElement7.f750x);
        SecP521R1Field.add(secP521R1FieldElement7.f750x, create6, secP521R1FieldElement7.f750x);
        SecP521R1Field.subtract(secP521R1FieldElement7.f750x, create3, secP521R1FieldElement7.f750x);
        SecP521R1Field.subtract(secP521R1FieldElement7.f750x, create3, secP521R1FieldElement7.f750x);
        SecP521R1FieldElement secP521R1FieldElement8 = new SecP521R1FieldElement(create6);
        SecP521R1Field.subtract(create3, secP521R1FieldElement7.f750x, secP521R1FieldElement8.f750x);
        SecP521R1Field.multiply(secP521R1FieldElement8.f750x, create2, create2);
        SecP521R1Field.subtract(create2, create, secP521R1FieldElement8.f750x);
        SecP521R1FieldElement secP521R1FieldElement9 = new SecP521R1FieldElement(create5);
        if (!isOne) {
            SecP521R1Field.multiply(secP521R1FieldElement9.f750x, secP521R1FieldElement5.f750x, secP521R1FieldElement9.f750x);
        }
        if (!isOne2) {
            SecP521R1Field.multiply(secP521R1FieldElement9.f750x, secP521R1FieldElement6.f750x, secP521R1FieldElement9.f750x);
        }
        return new SecP521R1Point(curve, secP521R1FieldElement7, secP521R1FieldElement8, new ECFieldElement[]{secP521R1FieldElement9});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecP521R1FieldElement secP521R1FieldElement = (SecP521R1FieldElement) this.f677y;
        if (secP521R1FieldElement.isZero()) {
            return curve.getInfinity();
        }
        SecP521R1FieldElement secP521R1FieldElement2 = (SecP521R1FieldElement) this.f676x;
        SecP521R1FieldElement secP521R1FieldElement3 = (SecP521R1FieldElement) this.f678zs[0];
        int[] create = Nat.create(17);
        int[] create2 = Nat.create(17);
        int[] create3 = Nat.create(17);
        SecP521R1Field.square(secP521R1FieldElement.f750x, create3);
        int[] create4 = Nat.create(17);
        SecP521R1Field.square(create3, create4);
        boolean isOne = secP521R1FieldElement3.isOne();
        int[] iArr = secP521R1FieldElement3.f750x;
        if (!isOne) {
            iArr = create2;
            SecP521R1Field.square(secP521R1FieldElement3.f750x, iArr);
        }
        SecP521R1Field.subtract(secP521R1FieldElement2.f750x, iArr, create);
        SecP521R1Field.add(secP521R1FieldElement2.f750x, iArr, create2);
        SecP521R1Field.multiply(create2, create, create2);
        Nat.addBothTo(17, create2, create2, create2);
        SecP521R1Field.reduce23(create2);
        SecP521R1Field.multiply(create3, secP521R1FieldElement2.f750x, create3);
        Nat.shiftUpBits(17, create3, 2, 0);
        SecP521R1Field.reduce23(create3);
        Nat.shiftUpBits(17, create4, 3, 0, create);
        SecP521R1Field.reduce23(create);
        SecP521R1FieldElement secP521R1FieldElement4 = new SecP521R1FieldElement(create4);
        SecP521R1Field.square(create2, secP521R1FieldElement4.f750x);
        SecP521R1Field.subtract(secP521R1FieldElement4.f750x, create3, secP521R1FieldElement4.f750x);
        SecP521R1Field.subtract(secP521R1FieldElement4.f750x, create3, secP521R1FieldElement4.f750x);
        SecP521R1FieldElement secP521R1FieldElement5 = new SecP521R1FieldElement(create3);
        SecP521R1Field.subtract(create3, secP521R1FieldElement4.f750x, secP521R1FieldElement5.f750x);
        SecP521R1Field.multiply(secP521R1FieldElement5.f750x, create2, secP521R1FieldElement5.f750x);
        SecP521R1Field.subtract(secP521R1FieldElement5.f750x, create, secP521R1FieldElement5.f750x);
        SecP521R1FieldElement secP521R1FieldElement6 = new SecP521R1FieldElement(create2);
        SecP521R1Field.twice(secP521R1FieldElement.f750x, secP521R1FieldElement6.f750x);
        if (!isOne) {
            SecP521R1Field.multiply(secP521R1FieldElement6.f750x, secP521R1FieldElement3.f750x, secP521R1FieldElement6.f750x);
        }
        return new SecP521R1Point(curve, secP521R1FieldElement4, secP521R1FieldElement5, new ECFieldElement[]{secP521R1FieldElement6});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        return this == eCPoint ? threeTimes() : isInfinity() ? eCPoint : eCPoint.isInfinity() ? twice() : this.f677y.isZero() ? eCPoint : twice().add(eCPoint);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint threeTimes() {
        return (isInfinity() || this.f677y.isZero()) ? this : twice().add(this);
    }

    protected ECFieldElement two(ECFieldElement eCFieldElement) {
        return eCFieldElement.add(eCFieldElement);
    }

    protected ECFieldElement three(ECFieldElement eCFieldElement) {
        return two(eCFieldElement).add(eCFieldElement);
    }

    protected ECFieldElement four(ECFieldElement eCFieldElement) {
        return two(two(eCFieldElement));
    }

    protected ECFieldElement eight(ECFieldElement eCFieldElement) {
        return four(two(eCFieldElement));
    }

    protected ECFieldElement doubleProductFromSquares(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3, ECFieldElement eCFieldElement4) {
        return eCFieldElement.add(eCFieldElement2).square().subtract(eCFieldElement3).subtract(eCFieldElement4);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new SecP521R1Point(this.curve, this.f676x, this.f677y.negate(), this.f678zs);
    }
}