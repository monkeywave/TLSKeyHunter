package org.bouncycastle.math.p010ec.custom.sec;

import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecP256R1Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecP256R1Point.class */
public class SecP256R1Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP256R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecP256R1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new SecP256R1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SecP256R1FieldElement secP256R1FieldElement = (SecP256R1FieldElement) this.f676x;
        SecP256R1FieldElement secP256R1FieldElement2 = (SecP256R1FieldElement) this.f677y;
        SecP256R1FieldElement secP256R1FieldElement3 = (SecP256R1FieldElement) eCPoint.getXCoord();
        SecP256R1FieldElement secP256R1FieldElement4 = (SecP256R1FieldElement) eCPoint.getYCoord();
        SecP256R1FieldElement secP256R1FieldElement5 = (SecP256R1FieldElement) this.f678zs[0];
        SecP256R1FieldElement secP256R1FieldElement6 = (SecP256R1FieldElement) eCPoint.getZCoord(0);
        int[] createExt = Nat256.createExt();
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        boolean isOne = secP256R1FieldElement5.isOne();
        if (isOne) {
            iArr2 = secP256R1FieldElement3.f741x;
            iArr = secP256R1FieldElement4.f741x;
        } else {
            iArr = create2;
            SecP256R1Field.square(secP256R1FieldElement5.f741x, iArr);
            iArr2 = create;
            SecP256R1Field.multiply(iArr, secP256R1FieldElement3.f741x, iArr2);
            SecP256R1Field.multiply(iArr, secP256R1FieldElement5.f741x, iArr);
            SecP256R1Field.multiply(iArr, secP256R1FieldElement4.f741x, iArr);
        }
        boolean isOne2 = secP256R1FieldElement6.isOne();
        if (isOne2) {
            iArr4 = secP256R1FieldElement.f741x;
            iArr3 = secP256R1FieldElement2.f741x;
        } else {
            iArr3 = create3;
            SecP256R1Field.square(secP256R1FieldElement6.f741x, iArr3);
            iArr4 = createExt;
            SecP256R1Field.multiply(iArr3, secP256R1FieldElement.f741x, iArr4);
            SecP256R1Field.multiply(iArr3, secP256R1FieldElement6.f741x, iArr3);
            SecP256R1Field.multiply(iArr3, secP256R1FieldElement2.f741x, iArr3);
        }
        int[] create4 = Nat256.create();
        SecP256R1Field.subtract(iArr4, iArr2, create4);
        SecP256R1Field.subtract(iArr3, iArr, create);
        if (Nat256.isZero(create4)) {
            return Nat256.isZero(create) ? twice() : curve.getInfinity();
        }
        SecP256R1Field.square(create4, create2);
        int[] create5 = Nat256.create();
        SecP256R1Field.multiply(create2, create4, create5);
        SecP256R1Field.multiply(create2, iArr4, create2);
        SecP256R1Field.negate(create5, create5);
        Nat256.mul(iArr3, create5, createExt);
        SecP256R1Field.reduce32(Nat256.addBothTo(create2, create2, create5), create5);
        SecP256R1FieldElement secP256R1FieldElement7 = new SecP256R1FieldElement(create3);
        SecP256R1Field.square(create, secP256R1FieldElement7.f741x);
        SecP256R1Field.subtract(secP256R1FieldElement7.f741x, create5, secP256R1FieldElement7.f741x);
        SecP256R1FieldElement secP256R1FieldElement8 = new SecP256R1FieldElement(create5);
        SecP256R1Field.subtract(create2, secP256R1FieldElement7.f741x, secP256R1FieldElement8.f741x);
        SecP256R1Field.multiplyAddToExt(secP256R1FieldElement8.f741x, create, createExt);
        SecP256R1Field.reduce(createExt, secP256R1FieldElement8.f741x);
        SecP256R1FieldElement secP256R1FieldElement9 = new SecP256R1FieldElement(create4);
        if (!isOne) {
            SecP256R1Field.multiply(secP256R1FieldElement9.f741x, secP256R1FieldElement5.f741x, secP256R1FieldElement9.f741x);
        }
        if (!isOne2) {
            SecP256R1Field.multiply(secP256R1FieldElement9.f741x, secP256R1FieldElement6.f741x, secP256R1FieldElement9.f741x);
        }
        return new SecP256R1Point(curve, secP256R1FieldElement7, secP256R1FieldElement8, new ECFieldElement[]{secP256R1FieldElement9});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SecP256R1FieldElement secP256R1FieldElement = (SecP256R1FieldElement) this.f677y;
        if (secP256R1FieldElement.isZero()) {
            return curve.getInfinity();
        }
        SecP256R1FieldElement secP256R1FieldElement2 = (SecP256R1FieldElement) this.f676x;
        SecP256R1FieldElement secP256R1FieldElement3 = (SecP256R1FieldElement) this.f678zs[0];
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        SecP256R1Field.square(secP256R1FieldElement.f741x, create3);
        int[] create4 = Nat256.create();
        SecP256R1Field.square(create3, create4);
        boolean isOne = secP256R1FieldElement3.isOne();
        int[] iArr = secP256R1FieldElement3.f741x;
        if (!isOne) {
            iArr = create2;
            SecP256R1Field.square(secP256R1FieldElement3.f741x, iArr);
        }
        SecP256R1Field.subtract(secP256R1FieldElement2.f741x, iArr, create);
        SecP256R1Field.add(secP256R1FieldElement2.f741x, iArr, create2);
        SecP256R1Field.multiply(create2, create, create2);
        SecP256R1Field.reduce32(Nat256.addBothTo(create2, create2, create2), create2);
        SecP256R1Field.multiply(create3, secP256R1FieldElement2.f741x, create3);
        SecP256R1Field.reduce32(Nat.shiftUpBits(8, create3, 2, 0), create3);
        SecP256R1Field.reduce32(Nat.shiftUpBits(8, create4, 3, 0, create), create);
        SecP256R1FieldElement secP256R1FieldElement4 = new SecP256R1FieldElement(create4);
        SecP256R1Field.square(create2, secP256R1FieldElement4.f741x);
        SecP256R1Field.subtract(secP256R1FieldElement4.f741x, create3, secP256R1FieldElement4.f741x);
        SecP256R1Field.subtract(secP256R1FieldElement4.f741x, create3, secP256R1FieldElement4.f741x);
        SecP256R1FieldElement secP256R1FieldElement5 = new SecP256R1FieldElement(create3);
        SecP256R1Field.subtract(create3, secP256R1FieldElement4.f741x, secP256R1FieldElement5.f741x);
        SecP256R1Field.multiply(secP256R1FieldElement5.f741x, create2, secP256R1FieldElement5.f741x);
        SecP256R1Field.subtract(secP256R1FieldElement5.f741x, create, secP256R1FieldElement5.f741x);
        SecP256R1FieldElement secP256R1FieldElement6 = new SecP256R1FieldElement(create2);
        SecP256R1Field.twice(secP256R1FieldElement.f741x, secP256R1FieldElement6.f741x);
        if (!isOne) {
            SecP256R1Field.multiply(secP256R1FieldElement6.f741x, secP256R1FieldElement3.f741x, secP256R1FieldElement6.f741x);
        }
        return new SecP256R1Point(curve, secP256R1FieldElement4, secP256R1FieldElement5, new ECFieldElement[]{secP256R1FieldElement6});
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
        return isInfinity() ? this : new SecP256R1Point(this.curve, this.f676x, this.f677y.negate(), this.f678zs);
    }
}