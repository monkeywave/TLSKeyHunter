package org.bouncycastle.math.p010ec.custom.p011gm;

import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.raw.Nat;
import org.bouncycastle.math.raw.Nat256;

/* renamed from: org.bouncycastle.math.ec.custom.gm.SM2P256V1Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/gm/SM2P256V1Point.class */
public class SM2P256V1Point extends ECPoint.AbstractFp {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SM2P256V1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SM2P256V1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new SM2P256V1Point(null, getAffineXCoord(), getAffineYCoord());
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
        SM2P256V1FieldElement sM2P256V1FieldElement = (SM2P256V1FieldElement) this.f676x;
        SM2P256V1FieldElement sM2P256V1FieldElement2 = (SM2P256V1FieldElement) this.f677y;
        SM2P256V1FieldElement sM2P256V1FieldElement3 = (SM2P256V1FieldElement) eCPoint.getXCoord();
        SM2P256V1FieldElement sM2P256V1FieldElement4 = (SM2P256V1FieldElement) eCPoint.getYCoord();
        SM2P256V1FieldElement sM2P256V1FieldElement5 = (SM2P256V1FieldElement) this.f678zs[0];
        SM2P256V1FieldElement sM2P256V1FieldElement6 = (SM2P256V1FieldElement) eCPoint.getZCoord(0);
        int[] createExt = Nat256.createExt();
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        boolean isOne = sM2P256V1FieldElement5.isOne();
        if (isOne) {
            iArr2 = sM2P256V1FieldElement3.f691x;
            iArr = sM2P256V1FieldElement4.f691x;
        } else {
            iArr = create2;
            SM2P256V1Field.square(sM2P256V1FieldElement5.f691x, iArr);
            iArr2 = create;
            SM2P256V1Field.multiply(iArr, sM2P256V1FieldElement3.f691x, iArr2);
            SM2P256V1Field.multiply(iArr, sM2P256V1FieldElement5.f691x, iArr);
            SM2P256V1Field.multiply(iArr, sM2P256V1FieldElement4.f691x, iArr);
        }
        boolean isOne2 = sM2P256V1FieldElement6.isOne();
        if (isOne2) {
            iArr4 = sM2P256V1FieldElement.f691x;
            iArr3 = sM2P256V1FieldElement2.f691x;
        } else {
            iArr3 = create3;
            SM2P256V1Field.square(sM2P256V1FieldElement6.f691x, iArr3);
            iArr4 = createExt;
            SM2P256V1Field.multiply(iArr3, sM2P256V1FieldElement.f691x, iArr4);
            SM2P256V1Field.multiply(iArr3, sM2P256V1FieldElement6.f691x, iArr3);
            SM2P256V1Field.multiply(iArr3, sM2P256V1FieldElement2.f691x, iArr3);
        }
        int[] create4 = Nat256.create();
        SM2P256V1Field.subtract(iArr4, iArr2, create4);
        SM2P256V1Field.subtract(iArr3, iArr, create);
        if (Nat256.isZero(create4)) {
            return Nat256.isZero(create) ? twice() : curve.getInfinity();
        }
        SM2P256V1Field.square(create4, create2);
        int[] create5 = Nat256.create();
        SM2P256V1Field.multiply(create2, create4, create5);
        SM2P256V1Field.multiply(create2, iArr4, create2);
        SM2P256V1Field.negate(create5, create5);
        Nat256.mul(iArr3, create5, createExt);
        SM2P256V1Field.reduce32(Nat256.addBothTo(create2, create2, create5), create5);
        SM2P256V1FieldElement sM2P256V1FieldElement7 = new SM2P256V1FieldElement(create3);
        SM2P256V1Field.square(create, sM2P256V1FieldElement7.f691x);
        SM2P256V1Field.subtract(sM2P256V1FieldElement7.f691x, create5, sM2P256V1FieldElement7.f691x);
        SM2P256V1FieldElement sM2P256V1FieldElement8 = new SM2P256V1FieldElement(create5);
        SM2P256V1Field.subtract(create2, sM2P256V1FieldElement7.f691x, sM2P256V1FieldElement8.f691x);
        SM2P256V1Field.multiplyAddToExt(sM2P256V1FieldElement8.f691x, create, createExt);
        SM2P256V1Field.reduce(createExt, sM2P256V1FieldElement8.f691x);
        SM2P256V1FieldElement sM2P256V1FieldElement9 = new SM2P256V1FieldElement(create4);
        if (!isOne) {
            SM2P256V1Field.multiply(sM2P256V1FieldElement9.f691x, sM2P256V1FieldElement5.f691x, sM2P256V1FieldElement9.f691x);
        }
        if (!isOne2) {
            SM2P256V1Field.multiply(sM2P256V1FieldElement9.f691x, sM2P256V1FieldElement6.f691x, sM2P256V1FieldElement9.f691x);
        }
        return new SM2P256V1Point(curve, sM2P256V1FieldElement7, sM2P256V1FieldElement8, new ECFieldElement[]{sM2P256V1FieldElement9});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        SM2P256V1FieldElement sM2P256V1FieldElement = (SM2P256V1FieldElement) this.f677y;
        if (sM2P256V1FieldElement.isZero()) {
            return curve.getInfinity();
        }
        SM2P256V1FieldElement sM2P256V1FieldElement2 = (SM2P256V1FieldElement) this.f676x;
        SM2P256V1FieldElement sM2P256V1FieldElement3 = (SM2P256V1FieldElement) this.f678zs[0];
        int[] create = Nat256.create();
        int[] create2 = Nat256.create();
        int[] create3 = Nat256.create();
        SM2P256V1Field.square(sM2P256V1FieldElement.f691x, create3);
        int[] create4 = Nat256.create();
        SM2P256V1Field.square(create3, create4);
        boolean isOne = sM2P256V1FieldElement3.isOne();
        int[] iArr = sM2P256V1FieldElement3.f691x;
        if (!isOne) {
            iArr = create2;
            SM2P256V1Field.square(sM2P256V1FieldElement3.f691x, iArr);
        }
        SM2P256V1Field.subtract(sM2P256V1FieldElement2.f691x, iArr, create);
        SM2P256V1Field.add(sM2P256V1FieldElement2.f691x, iArr, create2);
        SM2P256V1Field.multiply(create2, create, create2);
        SM2P256V1Field.reduce32(Nat256.addBothTo(create2, create2, create2), create2);
        SM2P256V1Field.multiply(create3, sM2P256V1FieldElement2.f691x, create3);
        SM2P256V1Field.reduce32(Nat.shiftUpBits(8, create3, 2, 0), create3);
        SM2P256V1Field.reduce32(Nat.shiftUpBits(8, create4, 3, 0, create), create);
        SM2P256V1FieldElement sM2P256V1FieldElement4 = new SM2P256V1FieldElement(create4);
        SM2P256V1Field.square(create2, sM2P256V1FieldElement4.f691x);
        SM2P256V1Field.subtract(sM2P256V1FieldElement4.f691x, create3, sM2P256V1FieldElement4.f691x);
        SM2P256V1Field.subtract(sM2P256V1FieldElement4.f691x, create3, sM2P256V1FieldElement4.f691x);
        SM2P256V1FieldElement sM2P256V1FieldElement5 = new SM2P256V1FieldElement(create3);
        SM2P256V1Field.subtract(create3, sM2P256V1FieldElement4.f691x, sM2P256V1FieldElement5.f691x);
        SM2P256V1Field.multiply(sM2P256V1FieldElement5.f691x, create2, sM2P256V1FieldElement5.f691x);
        SM2P256V1Field.subtract(sM2P256V1FieldElement5.f691x, create, sM2P256V1FieldElement5.f691x);
        SM2P256V1FieldElement sM2P256V1FieldElement6 = new SM2P256V1FieldElement(create2);
        SM2P256V1Field.twice(sM2P256V1FieldElement.f691x, sM2P256V1FieldElement6.f691x);
        if (!isOne) {
            SM2P256V1Field.multiply(sM2P256V1FieldElement6.f691x, sM2P256V1FieldElement3.f691x, sM2P256V1FieldElement6.f691x);
        }
        return new SM2P256V1Point(curve, sM2P256V1FieldElement4, sM2P256V1FieldElement5, new ECFieldElement[]{sM2P256V1FieldElement6});
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
        return isInfinity() ? this : new SM2P256V1Point(this.curve, this.f676x, this.f677y.negate(), this.f678zs);
    }
}