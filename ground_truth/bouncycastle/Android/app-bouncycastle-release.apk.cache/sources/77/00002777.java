package org.bouncycastle.math.p016ec.custom.sec;

import org.bouncycastle.math.p016ec.ECConstants;
import org.bouncycastle.math.p016ec.ECCurve;
import org.bouncycastle.math.p016ec.ECFieldElement;
import org.bouncycastle.math.p016ec.ECPoint;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT163K1Point */
/* loaded from: classes2.dex */
public class SecT163K1Point extends ECPoint.AbstractF2m {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecT163K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecT163K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint add(ECPoint eCPoint) {
        ECFieldElement eCFieldElement;
        ECFieldElement eCFieldElement2;
        ECFieldElement eCFieldElement3;
        ECFieldElement eCFieldElement4;
        ECFieldElement eCFieldElement5;
        ECFieldElement eCFieldElement6;
        if (isInfinity()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement7 = this.f1015x;
        ECFieldElement rawXCoord = eCPoint.getRawXCoord();
        if (eCFieldElement7.isZero()) {
            return rawXCoord.isZero() ? curve.getInfinity() : eCPoint.add(this);
        }
        ECFieldElement eCFieldElement8 = this.f1016y;
        ECFieldElement eCFieldElement9 = this.f1017zs[0];
        ECFieldElement rawYCoord = eCPoint.getRawYCoord();
        ECFieldElement zCoord = eCPoint.getZCoord(0);
        boolean isOne = eCFieldElement9.isOne();
        if (isOne) {
            eCFieldElement = rawXCoord;
            eCFieldElement2 = rawYCoord;
        } else {
            eCFieldElement = rawXCoord.multiply(eCFieldElement9);
            eCFieldElement2 = rawYCoord.multiply(eCFieldElement9);
        }
        boolean isOne2 = zCoord.isOne();
        if (isOne2) {
            eCFieldElement3 = eCFieldElement8;
        } else {
            eCFieldElement7 = eCFieldElement7.multiply(zCoord);
            eCFieldElement3 = eCFieldElement8.multiply(zCoord);
        }
        ECFieldElement add = eCFieldElement3.add(eCFieldElement2);
        ECFieldElement add2 = eCFieldElement7.add(eCFieldElement);
        if (add2.isZero()) {
            return add.isZero() ? twice() : curve.getInfinity();
        }
        if (rawXCoord.isZero()) {
            ECPoint normalize = normalize();
            ECFieldElement xCoord = normalize.getXCoord();
            ECFieldElement yCoord = normalize.getYCoord();
            ECFieldElement divide = yCoord.add(rawYCoord).divide(xCoord);
            eCFieldElement4 = divide.square().add(divide).add(xCoord).addOne();
            if (eCFieldElement4.isZero()) {
                return new SecT163K1Point(curve, eCFieldElement4, curve.getB());
            }
            eCFieldElement6 = divide.multiply(xCoord.add(eCFieldElement4)).add(eCFieldElement4).add(yCoord).divide(eCFieldElement4).add(eCFieldElement4);
            eCFieldElement5 = curve.fromBigInteger(ECConstants.ONE);
        } else {
            ECFieldElement square = add2.square();
            ECFieldElement multiply = add.multiply(eCFieldElement7);
            ECFieldElement multiply2 = add.multiply(eCFieldElement);
            ECFieldElement multiply3 = multiply.multiply(multiply2);
            if (multiply3.isZero()) {
                return new SecT163K1Point(curve, multiply3, curve.getB());
            }
            ECFieldElement multiply4 = add.multiply(square);
            ECFieldElement multiply5 = !isOne2 ? multiply4.multiply(zCoord) : multiply4;
            ECFieldElement squarePlusProduct = multiply2.add(square).squarePlusProduct(multiply5, eCFieldElement8.add(eCFieldElement9));
            if (!isOne) {
                multiply5 = multiply5.multiply(eCFieldElement9);
            }
            eCFieldElement4 = multiply3;
            eCFieldElement5 = multiply5;
            eCFieldElement6 = squarePlusProduct;
        }
        return new SecT163K1Point(curve, eCFieldElement4, eCFieldElement6, new ECFieldElement[]{eCFieldElement5});
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    protected ECPoint detach() {
        return new SecT163K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    protected boolean getCompressionYTilde() {
        ECFieldElement rawXCoord = getRawXCoord();
        return (rawXCoord.isZero() || getRawYCoord().testBitZero() == rawXCoord.testBitZero()) ? false : true;
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECFieldElement getYCoord() {
        ECFieldElement eCFieldElement = this.f1015x;
        ECFieldElement eCFieldElement2 = this.f1016y;
        if (isInfinity() || eCFieldElement.isZero()) {
            return eCFieldElement2;
        }
        ECFieldElement multiply = eCFieldElement2.add(eCFieldElement).multiply(eCFieldElement);
        ECFieldElement eCFieldElement3 = this.f1017zs[0];
        return !eCFieldElement3.isOne() ? multiply.divide(eCFieldElement3) : multiply;
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint negate() {
        if (isInfinity()) {
            return this;
        }
        ECFieldElement eCFieldElement = this.f1015x;
        if (eCFieldElement.isZero()) {
            return this;
        }
        ECFieldElement eCFieldElement2 = this.f1016y;
        ECFieldElement eCFieldElement3 = this.f1017zs[0];
        return new SecT163K1Point(this.curve, eCFieldElement, eCFieldElement2.add(eCFieldElement3), new ECFieldElement[]{eCFieldElement3});
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement = this.f1015x;
        if (eCFieldElement.isZero()) {
            return curve.getInfinity();
        }
        ECFieldElement eCFieldElement2 = this.f1016y;
        ECFieldElement eCFieldElement3 = this.f1017zs[0];
        boolean isOne = eCFieldElement3.isOne();
        ECFieldElement multiply = isOne ? eCFieldElement2 : eCFieldElement2.multiply(eCFieldElement3);
        if (!isOne) {
            eCFieldElement3 = eCFieldElement3.square();
        }
        ECFieldElement add = eCFieldElement2.square().add(multiply).add(eCFieldElement3);
        if (add.isZero()) {
            return new SecT163K1Point(curve, add, curve.getB());
        }
        ECFieldElement square = add.square();
        ECFieldElement multiply2 = isOne ? add : add.multiply(eCFieldElement3);
        ECFieldElement square2 = eCFieldElement2.add(eCFieldElement).square();
        return new SecT163K1Point(curve, square, square2.add(add).add(eCFieldElement3).multiply(square2).add(square), new ECFieldElement[]{multiply2});
    }

    @Override // org.bouncycastle.math.p016ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        if (isInfinity()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return twice();
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement = this.f1015x;
        if (eCFieldElement.isZero()) {
            return eCPoint;
        }
        ECFieldElement rawXCoord = eCPoint.getRawXCoord();
        ECFieldElement zCoord = eCPoint.getZCoord(0);
        if (rawXCoord.isZero() || !zCoord.isOne()) {
            return twice().add(eCPoint);
        }
        ECFieldElement eCFieldElement2 = this.f1016y;
        ECFieldElement eCFieldElement3 = this.f1017zs[0];
        ECFieldElement rawYCoord = eCPoint.getRawYCoord();
        ECFieldElement square = eCFieldElement.square();
        ECFieldElement square2 = eCFieldElement2.square();
        ECFieldElement square3 = eCFieldElement3.square();
        ECFieldElement add = square3.add(square2).add(eCFieldElement2.multiply(eCFieldElement3));
        ECFieldElement multiplyPlusProduct = rawYCoord.multiply(square3).add(square2).multiplyPlusProduct(add, square, square3);
        ECFieldElement multiply = rawXCoord.multiply(square3);
        ECFieldElement square4 = multiply.add(add).square();
        if (square4.isZero()) {
            return multiplyPlusProduct.isZero() ? eCPoint.twice() : curve.getInfinity();
        } else if (multiplyPlusProduct.isZero()) {
            return new SecT163K1Point(curve, multiplyPlusProduct, curve.getB());
        } else {
            ECFieldElement multiply2 = multiplyPlusProduct.square().multiply(multiply);
            ECFieldElement multiply3 = multiplyPlusProduct.multiply(square4).multiply(square3);
            return new SecT163K1Point(curve, multiply2, multiplyPlusProduct.add(square4).square().multiplyPlusProduct(add, rawYCoord.addOne(), multiply3), new ECFieldElement[]{multiply3});
        }
    }
}