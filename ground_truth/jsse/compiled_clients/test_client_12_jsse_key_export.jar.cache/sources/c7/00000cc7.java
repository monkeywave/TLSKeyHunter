package org.bouncycastle.math.p010ec.custom.sec;

import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;
import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.math.ec.custom.sec.SecT233K1Point */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/custom/sec/SecT233K1Point.class */
public class SecT233K1Point extends ECPoint.AbstractF2m {
    /* JADX INFO: Access modifiers changed from: package-private */
    public SecT233K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        super(eCCurve, eCFieldElement, eCFieldElement2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SecT233K1Point(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected ECPoint detach() {
        return new SecT233K1Point(null, getAffineXCoord(), getAffineYCoord());
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECFieldElement getYCoord() {
        ECFieldElement eCFieldElement = this.f676x;
        ECFieldElement eCFieldElement2 = this.f677y;
        if (isInfinity() || eCFieldElement.isZero()) {
            return eCFieldElement2;
        }
        ECFieldElement multiply = eCFieldElement2.add(eCFieldElement).multiply(eCFieldElement);
        ECFieldElement eCFieldElement3 = this.f678zs[0];
        if (!eCFieldElement3.isOne()) {
            multiply = multiply.divide(eCFieldElement3);
        }
        return multiply;
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    protected boolean getCompressionYTilde() {
        ECFieldElement rawXCoord = getRawXCoord();
        return (rawXCoord.isZero() || getRawYCoord().testBitZero() == rawXCoord.testBitZero()) ? false : true;
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint add(ECPoint eCPoint) {
        ECFieldElement multiply;
        ECFieldElement squarePlusProduct;
        ECFieldElement eCFieldElement;
        if (isInfinity()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement2 = this.f676x;
        ECFieldElement rawXCoord = eCPoint.getRawXCoord();
        if (eCFieldElement2.isZero()) {
            return rawXCoord.isZero() ? curve.getInfinity() : eCPoint.add(this);
        }
        ECFieldElement eCFieldElement3 = this.f677y;
        ECFieldElement eCFieldElement4 = this.f678zs[0];
        ECFieldElement rawYCoord = eCPoint.getRawYCoord();
        ECFieldElement zCoord = eCPoint.getZCoord(0);
        boolean isOne = eCFieldElement4.isOne();
        ECFieldElement eCFieldElement5 = rawXCoord;
        ECFieldElement eCFieldElement6 = rawYCoord;
        if (!isOne) {
            eCFieldElement5 = eCFieldElement5.multiply(eCFieldElement4);
            eCFieldElement6 = eCFieldElement6.multiply(eCFieldElement4);
        }
        boolean isOne2 = zCoord.isOne();
        ECFieldElement eCFieldElement7 = eCFieldElement2;
        ECFieldElement eCFieldElement8 = eCFieldElement3;
        if (!isOne2) {
            eCFieldElement7 = eCFieldElement7.multiply(zCoord);
            eCFieldElement8 = eCFieldElement8.multiply(zCoord);
        }
        ECFieldElement add = eCFieldElement8.add(eCFieldElement6);
        ECFieldElement add2 = eCFieldElement7.add(eCFieldElement5);
        if (add2.isZero()) {
            return add.isZero() ? twice() : curve.getInfinity();
        }
        if (rawXCoord.isZero()) {
            ECPoint normalize = normalize();
            ECFieldElement xCoord = normalize.getXCoord();
            ECFieldElement yCoord = normalize.getYCoord();
            ECFieldElement divide = yCoord.add(rawYCoord).divide(xCoord);
            multiply = divide.square().add(divide).add(xCoord);
            if (multiply.isZero()) {
                return new SecT233K1Point(curve, multiply, curve.getB());
            }
            squarePlusProduct = divide.multiply(xCoord.add(multiply)).add(multiply).add(yCoord).divide(multiply).add(multiply);
            eCFieldElement = curve.fromBigInteger(ECConstants.ONE);
        } else {
            ECFieldElement square = add2.square();
            ECFieldElement multiply2 = add.multiply(eCFieldElement7);
            ECFieldElement multiply3 = add.multiply(eCFieldElement5);
            multiply = multiply2.multiply(multiply3);
            if (multiply.isZero()) {
                return new SecT233K1Point(curve, multiply, curve.getB());
            }
            ECFieldElement multiply4 = add.multiply(square);
            if (!isOne2) {
                multiply4 = multiply4.multiply(zCoord);
            }
            squarePlusProduct = multiply3.add(square).squarePlusProduct(multiply4, eCFieldElement3.add(eCFieldElement4));
            eCFieldElement = multiply4;
            if (!isOne) {
                eCFieldElement = eCFieldElement.multiply(eCFieldElement4);
            }
        }
        return new SecT233K1Point(curve, multiply, squarePlusProduct, new ECFieldElement[]{eCFieldElement});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twice() {
        if (isInfinity()) {
            return this;
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement = this.f676x;
        if (eCFieldElement.isZero()) {
            return curve.getInfinity();
        }
        ECFieldElement eCFieldElement2 = this.f677y;
        ECFieldElement eCFieldElement3 = this.f678zs[0];
        boolean isOne = eCFieldElement3.isOne();
        ECFieldElement square = isOne ? eCFieldElement3 : eCFieldElement3.square();
        ECFieldElement add = isOne ? eCFieldElement2.square().add(eCFieldElement2) : eCFieldElement2.add(eCFieldElement3).multiply(eCFieldElement2);
        if (add.isZero()) {
            return new SecT233K1Point(curve, add, curve.getB());
        }
        ECFieldElement square2 = add.square();
        ECFieldElement multiply = isOne ? add : add.multiply(square);
        ECFieldElement square3 = eCFieldElement2.add(eCFieldElement).square();
        return new SecT233K1Point(curve, square2, square3.add(add).add(square).multiply(square3).add(isOne ? eCFieldElement3 : square.square()).add(square2).add(multiply), new ECFieldElement[]{multiply});
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint twicePlus(ECPoint eCPoint) {
        if (isInfinity()) {
            return eCPoint;
        }
        if (eCPoint.isInfinity()) {
            return twice();
        }
        ECCurve curve = getCurve();
        ECFieldElement eCFieldElement = this.f676x;
        if (eCFieldElement.isZero()) {
            return eCPoint;
        }
        ECFieldElement rawXCoord = eCPoint.getRawXCoord();
        ECFieldElement zCoord = eCPoint.getZCoord(0);
        if (rawXCoord.isZero() || !zCoord.isOne()) {
            return twice().add(eCPoint);
        }
        ECFieldElement eCFieldElement2 = this.f677y;
        ECFieldElement eCFieldElement3 = this.f678zs[0];
        ECFieldElement rawYCoord = eCPoint.getRawYCoord();
        ECFieldElement square = eCFieldElement.square();
        ECFieldElement square2 = eCFieldElement2.square();
        ECFieldElement square3 = eCFieldElement3.square();
        ECFieldElement add = square2.add(eCFieldElement2.multiply(eCFieldElement3));
        ECFieldElement addOne = rawYCoord.addOne();
        ECFieldElement multiplyPlusProduct = addOne.multiply(square3).add(square2).multiplyPlusProduct(add, square, square3);
        ECFieldElement multiply = rawXCoord.multiply(square3);
        ECFieldElement square4 = multiply.add(add).square();
        if (square4.isZero()) {
            return multiplyPlusProduct.isZero() ? eCPoint.twice() : curve.getInfinity();
        } else if (multiplyPlusProduct.isZero()) {
            return new SecT233K1Point(curve, multiplyPlusProduct, curve.getB());
        } else {
            ECFieldElement multiply2 = multiplyPlusProduct.square().multiply(multiply);
            ECFieldElement multiply3 = multiplyPlusProduct.multiply(square4).multiply(square3);
            return new SecT233K1Point(curve, multiply2, multiplyPlusProduct.add(square4).square().multiplyPlusProduct(add, addOne, multiply3), new ECFieldElement[]{multiply3});
        }
    }

    @Override // org.bouncycastle.math.p010ec.ECPoint
    public ECPoint negate() {
        if (isInfinity()) {
            return this;
        }
        ECFieldElement eCFieldElement = this.f676x;
        if (eCFieldElement.isZero()) {
            return this;
        }
        ECFieldElement eCFieldElement2 = this.f677y;
        ECFieldElement eCFieldElement3 = this.f678zs[0];
        return new SecT233K1Point(this.curve, eCFieldElement, eCFieldElement2.add(eCFieldElement3), new ECFieldElement[]{eCFieldElement3});
    }
}