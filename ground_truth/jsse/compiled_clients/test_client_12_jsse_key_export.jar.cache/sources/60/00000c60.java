package org.bouncycastle.math.p010ec.custom.djb;

import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.custom.djb.Curve25519Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/djb/Curve25519Point.class */
public class Curve25519Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public Curve25519Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Curve25519Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new Curve25519Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECFieldElement getZCoord(int i) {
        return i == 1 ? getJacobianModifiedW() : super.getZCoord(i);
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
        Curve25519FieldElement curve25519FieldElement = (Curve25519FieldElement) this.f676x;
        Curve25519FieldElement curve25519FieldElement2 = (Curve25519FieldElement) this.f677y;
        Curve25519FieldElement curve25519FieldElement3 = (Curve25519FieldElement) this.f678zs[0];
        Curve25519FieldElement curve25519FieldElement4 = (Curve25519FieldElement) eCPoint.getXCoord();
        Curve25519FieldElement curve25519FieldElement5 = (Curve25519FieldElement) eCPoint.getYCoord();
        Curve25519FieldElement curve25519FieldElement6 = (Curve25519FieldElement) eCPoint.getZCoord(0);
        int[] createExt = Nat256.createExt();
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        boolean isOne = curve25519FieldElement3.isOne();
        if (isOne) {
            iArr2 = curve25519FieldElement4.f686x;
            iArr = curve25519FieldElement5.f686x;
        } else {
            iArr = create2;
            Curve25519Field.square(curve25519FieldElement3.f686x, iArr);
            iArr2 = create;
            Curve25519Field.multiply(iArr, curve25519FieldElement4.f686x, iArr2);
            Curve25519Field.multiply(iArr, curve25519FieldElement3.f686x, iArr);
            Curve25519Field.multiply(iArr, curve25519FieldElement5.f686x, iArr);
        }
        boolean isOne2 = curve25519FieldElement6.isOne();
        if (isOne2) {
            iArr4 = curve25519FieldElement.f686x;
            iArr3 = curve25519FieldElement2.f686x;
        } else {
            iArr3 = create3;
            Curve25519Field.square(curve25519FieldElement6.f686x, iArr3);
            iArr4 = createExt;
            Curve25519Field.multiply(iArr3, curve25519FieldElement.f686x, iArr4);
            Curve25519Field.multiply(iArr3, curve25519FieldElement6.f686x, iArr3);
            Curve25519Field.multiply(iArr3, curve25519FieldElement2.f686x, iArr3);
        }
        int[] create4 = Nat256.create();
        Curve25519Field.subtract(iArr4, iArr2, create4);
        Curve25519Field.subtract(iArr3, iArr, create);
        if (Nat256.isZero(create4)) {
            return Nat256.isZero(create) ? twice() : curve.getInfinity();
        }
        int[] create5 = Nat256.create();
        Curve25519Field.square(create4, create5);
        int[] create6 = Nat256.create();
        Curve25519Field.multiply(create5, create4, create6);
        Curve25519Field.multiply(create5, iArr4, create2);
        Curve25519Field.negate(create6, create6);
        Nat256.mul(iArr3, create6, createExt);
        Curve25519Field.reduce27(Nat256.addBothTo(create2, create2, create6), create6);
        Curve25519FieldElement curve25519FieldElement7 = new Curve25519FieldElement(create3);
        Curve25519Field.square(create, curve25519FieldElement7.f686x);
        Curve25519Field.subtract(curve25519FieldElement7.f686x, create6, curve25519FieldElement7.f686x);
        Curve25519FieldElement curve25519FieldElement8 = new Curve25519FieldElement(create6);
        Curve25519Field.subtract(create2, curve25519FieldElement7.f686x, curve25519FieldElement8.f686x);
        Curve25519Field.multiplyAddToExt(curve25519FieldElement8.f686x, create, createExt);
        Curve25519Field.reduce(createExt, curve25519FieldElement8.f686x);
        Curve25519FieldElement curve25519FieldElement9 = new Curve25519FieldElement(create4);
        if (!isOne) {
            Curve25519Field.multiply(curve25519FieldElement9.f686x, curve25519FieldElement3.f686x, curve25519FieldElement9.f686x);
        }
        if (!isOne2) {
            Curve25519Field.multiply(curve25519FieldElement9.f686x, curve25519FieldElement6.f686x, curve25519FieldElement9.f686x);
        }
        return new Curve25519Point(curve, curve25519FieldElement7, curve25519FieldElement8, new ECFieldElement[]{curve25519FieldElement9, calculateJacobianModifiedW(curve25519FieldElement9, (isOne && isOne2) ? create5 : null)});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        return this.f677y.isZero() ? getCurve().getInfinity() : twiceJacobianModified(true);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        return this == eCPoint ? threeTimes() : isInfinity() ? eCPoint : eCPoint.isInfinity() ? twice() : this.f677y.isZero() ? eCPoint : twiceJacobianModified(false).add(eCPoint);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint threeTimes() {
        if (!isInfinity() && !this.f677y.isZero()) {
            return twiceJacobianModified(false).add(this);
        }
        return this;
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint negate() {
        return isInfinity() ? this : new Curve25519Point(getCurve(), this.f676x, this.f677y.negate(), this.f678zs);
    }

    protected Curve25519FieldElement calculateJacobianModifiedW(Curve25519FieldElement curve25519FieldElement, int[] iArr) {
        Curve25519FieldElement curve25519FieldElement2 = (Curve25519FieldElement) getCurve().getA();
        if (curve25519FieldElement.isOne()) {
            return curve25519FieldElement2;
        }
        Curve25519FieldElement curve25519FieldElement3 = new Curve25519FieldElement();
        if (iArr == null) {
            iArr = curve25519FieldElement3.f686x;
            Curve25519Field.square(curve25519FieldElement.f686x, iArr);
        }
        Curve25519Field.square(iArr, curve25519FieldElement3.f686x);
        Curve25519Field.multiply(curve25519FieldElement3.f686x, curve25519FieldElement2.f686x, curve25519FieldElement3.f686x);
        return curve25519FieldElement3;
    }

    protected Curve25519FieldElement getJacobianModifiedW() {
        Curve25519FieldElement curve25519FieldElement = (Curve25519FieldElement) this.f678zs[1];
        if (curve25519FieldElement == null) {
            ECFieldElement[] eCFieldElementArr = this.f678zs;
            Curve25519FieldElement calculateJacobianModifiedW = calculateJacobianModifiedW((Curve25519FieldElement) this.f678zs[0], null);
            curve25519FieldElement = calculateJacobianModifiedW;
            eCFieldElementArr[1] = calculateJacobianModifiedW;
        }
        return curve25519FieldElement;
    }

    protected Curve25519Point twiceJacobianModified(boolean z) {
        Curve25519FieldElement curve25519FieldElement = (Curve25519FieldElement) this.f676x;
        Curve25519FieldElement curve25519FieldElement2 = (Curve25519FieldElement) this.f677y;
        Curve25519FieldElement curve25519FieldElement3 = (Curve25519FieldElement) this.f678zs[0];
        Curve25519FieldElement jacobianModifiedW = getJacobianModifiedW();
        int[] create = Nat256.create();
        Curve25519Field.square(curve25519FieldElement.f686x, create);
        Curve25519Field.reduce27(Nat256.addBothTo(create, create, create) + Nat256.addTo(jacobianModifiedW.f686x, create), create);
        int[] create2 = Nat256.create();
        Curve25519Field.twice(curve25519FieldElement2.f686x, create2);
        int[] create3 = Nat256.create();
        Curve25519Field.multiply(create2, curve25519FieldElement2.f686x, create3);
        int[] create4 = Nat256.create();
        Curve25519Field.multiply(create3, curve25519FieldElement.f686x, create4);
        Curve25519Field.twice(create4, create4);
        int[] create5 = Nat256.create();
        Curve25519Field.square(create3, create5);
        Curve25519Field.twice(create5, create5);
        Curve25519FieldElement curve25519FieldElement4 = new Curve25519FieldElement(create3);
        Curve25519Field.square(create, curve25519FieldElement4.f686x);
        Curve25519Field.subtract(curve25519FieldElement4.f686x, create4, curve25519FieldElement4.f686x);
        Curve25519Field.subtract(curve25519FieldElement4.f686x, create4, curve25519FieldElement4.f686x);
        Curve25519FieldElement curve25519FieldElement5 = new Curve25519FieldElement(create4);
        Curve25519Field.subtract(create4, curve25519FieldElement4.f686x, curve25519FieldElement5.f686x);
        Curve25519Field.multiply(curve25519FieldElement5.f686x, create, curve25519FieldElement5.f686x);
        Curve25519Field.subtract(curve25519FieldElement5.f686x, create5, curve25519FieldElement5.f686x);
        Curve25519FieldElement curve25519FieldElement6 = new Curve25519FieldElement(create2);
        if (!Nat256.isOne(curve25519FieldElement3.f686x)) {
            Curve25519Field.multiply(curve25519FieldElement6.f686x, curve25519FieldElement3.f686x, curve25519FieldElement6.f686x);
        }
        Curve25519FieldElement curve25519FieldElement7 = null;
        if (z) {
            curve25519FieldElement7 = new Curve25519FieldElement(create5);
            Curve25519Field.multiply(curve25519FieldElement7.f686x, jacobianModifiedW.f686x, curve25519FieldElement7.f686x);
            Curve25519Field.twice(curve25519FieldElement7.f686x, curve25519FieldElement7.f686x);
        }
        return new Curve25519Point(getCurve(), curve25519FieldElement4, curve25519FieldElement5, new ECFieldElement[]{curve25519FieldElement6, curve25519FieldElement7});
    }
}