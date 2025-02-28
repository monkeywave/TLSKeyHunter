package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import java.util.Hashtable;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECFieldElement;

/* renamed from: org.bouncycastle.math.ec.ECPoint */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECPoint.class */
public abstract class ECPoint {
    protected static final ECFieldElement[] EMPTY_ZS = new ECFieldElement[0];
    protected ECCurve curve;

    /* renamed from: x */
    protected ECFieldElement f676x;

    /* renamed from: y */
    protected ECFieldElement f677y;

    /* renamed from: zs */
    protected ECFieldElement[] f678zs;
    protected Hashtable preCompTable;

    /* renamed from: org.bouncycastle.math.ec.ECPoint$AbstractF2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECPoint$AbstractF2m.class */
    public static abstract class AbstractF2m extends ECPoint {
        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractF2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractF2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected boolean satisfiesCurveEquation() {
            ECFieldElement multiplyPlusProduct;
            ECFieldElement squarePlusProduct;
            ECCurve curve = getCurve();
            ECFieldElement eCFieldElement = this.f676x;
            ECFieldElement a = curve.getA();
            ECFieldElement b = curve.getB();
            int coordinateSystem = curve.getCoordinateSystem();
            if (coordinateSystem != 6) {
                ECFieldElement eCFieldElement2 = this.f677y;
                ECFieldElement multiply = eCFieldElement2.add(eCFieldElement).multiply(eCFieldElement2);
                switch (coordinateSystem) {
                    case 0:
                        break;
                    default:
                        throw new IllegalStateException("unsupported coordinate system");
                    case 1:
                        ECFieldElement eCFieldElement3 = this.f678zs[0];
                        if (!eCFieldElement3.isOne()) {
                            ECFieldElement multiply2 = eCFieldElement3.multiply(eCFieldElement3.square());
                            multiply = multiply.multiply(eCFieldElement3);
                            a = a.multiply(eCFieldElement3);
                            b = b.multiply(multiply2);
                            break;
                        }
                        break;
                }
                return multiply.equals(eCFieldElement.add(a).multiply(eCFieldElement.square()).add(b));
            }
            ECFieldElement eCFieldElement4 = this.f678zs[0];
            boolean isOne = eCFieldElement4.isOne();
            if (eCFieldElement.isZero()) {
                ECFieldElement square = this.f677y.square();
                ECFieldElement eCFieldElement5 = b;
                if (!isOne) {
                    eCFieldElement5 = eCFieldElement5.multiply(eCFieldElement4.square());
                }
                return square.equals(eCFieldElement5);
            }
            ECFieldElement eCFieldElement6 = this.f677y;
            ECFieldElement square2 = eCFieldElement.square();
            if (isOne) {
                multiplyPlusProduct = eCFieldElement6.square().add(eCFieldElement6).add(a);
                squarePlusProduct = square2.square().add(b);
            } else {
                ECFieldElement square3 = eCFieldElement4.square();
                ECFieldElement square4 = square3.square();
                multiplyPlusProduct = eCFieldElement6.add(eCFieldElement4).multiplyPlusProduct(eCFieldElement6, a, square3);
                squarePlusProduct = square2.squarePlusProduct(b, square4);
            }
            return multiplyPlusProduct.multiply(square2).equals(squarePlusProduct);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected boolean satisfiesOrder() {
            BigInteger cofactor = this.curve.getCofactor();
            if (ECConstants.TWO.equals(cofactor)) {
                return 0 != ((ECFieldElement.AbstractF2m) normalize().getAffineXCoord()).trace();
            } else if (ECConstants.FOUR.equals(cofactor)) {
                ECPoint normalize = normalize();
                ECFieldElement affineXCoord = normalize.getAffineXCoord();
                ECFieldElement solveQuadraticEquation = ((ECCurve.AbstractF2m) this.curve).solveQuadraticEquation(affineXCoord.add(this.curve.getA()));
                if (null == solveQuadraticEquation) {
                    return false;
                }
                return 0 == ((ECFieldElement.AbstractF2m) affineXCoord.multiply(solveQuadraticEquation).add(normalize.getAffineYCoord())).trace();
            } else {
                return super.satisfiesOrder();
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint scaleX(ECFieldElement eCFieldElement) {
            if (isInfinity()) {
                return this;
            }
            switch (getCurveCoordinateSystem()) {
                case 5:
                    ECFieldElement rawXCoord = getRawXCoord();
                    return getCurve().createRawPoint(rawXCoord, getRawYCoord().add(rawXCoord).divide(eCFieldElement).add(rawXCoord.multiply(eCFieldElement)), getRawZCoords());
                case 6:
                    ECFieldElement rawXCoord2 = getRawXCoord();
                    ECFieldElement rawYCoord = getRawYCoord();
                    ECFieldElement eCFieldElement2 = getRawZCoords()[0];
                    ECFieldElement multiply = rawXCoord2.multiply(eCFieldElement.square());
                    return getCurve().createRawPoint(multiply, rawYCoord.add(rawXCoord2).add(multiply), new ECFieldElement[]{eCFieldElement2.multiply(eCFieldElement)});
                default:
                    return super.scaleX(eCFieldElement);
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint scaleXNegateY(ECFieldElement eCFieldElement) {
            return scaleX(eCFieldElement);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint scaleY(ECFieldElement eCFieldElement) {
            if (isInfinity()) {
                return this;
            }
            switch (getCurveCoordinateSystem()) {
                case 5:
                case 6:
                    ECFieldElement rawXCoord = getRawXCoord();
                    return getCurve().createRawPoint(rawXCoord, getRawYCoord().add(rawXCoord).multiply(eCFieldElement).add(rawXCoord), getRawZCoords());
                default:
                    return super.scaleY(eCFieldElement);
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint scaleYNegateX(ECFieldElement eCFieldElement) {
            return scaleY(eCFieldElement);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint subtract(ECPoint eCPoint) {
            return eCPoint.isInfinity() ? this : add(eCPoint.negate());
        }

        public AbstractF2m tau() {
            if (isInfinity()) {
                return this;
            }
            ECCurve curve = getCurve();
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement eCFieldElement = this.f676x;
            switch (coordinateSystem) {
                case 0:
                case 5:
                    return (AbstractF2m) curve.createRawPoint(eCFieldElement.square(), this.f677y.square());
                case 1:
                case 6:
                    return (AbstractF2m) curve.createRawPoint(eCFieldElement.square(), this.f677y.square(), new ECFieldElement[]{this.f678zs[0].square()});
                case 2:
                case 3:
                case 4:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
        }

        public AbstractF2m tauPow(int i) {
            if (isInfinity()) {
                return this;
            }
            ECCurve curve = getCurve();
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement eCFieldElement = this.f676x;
            switch (coordinateSystem) {
                case 0:
                case 5:
                    return (AbstractF2m) curve.createRawPoint(eCFieldElement.squarePow(i), this.f677y.squarePow(i));
                case 1:
                case 6:
                    return (AbstractF2m) curve.createRawPoint(eCFieldElement.squarePow(i), this.f677y.squarePow(i), new ECFieldElement[]{this.f678zs[0].squarePow(i)});
                case 2:
                case 3:
                case 4:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECPoint$AbstractFp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECPoint$AbstractFp.class */
    public static abstract class AbstractFp extends ECPoint {
        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractFp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
        }

        /* JADX INFO: Access modifiers changed from: protected */
        public AbstractFp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected boolean getCompressionYTilde() {
            return getAffineYCoord().testBitZero();
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected boolean satisfiesCurveEquation() {
            ECFieldElement eCFieldElement = this.f676x;
            ECFieldElement eCFieldElement2 = this.f677y;
            ECFieldElement a = this.curve.getA();
            ECFieldElement b = this.curve.getB();
            ECFieldElement square = eCFieldElement2.square();
            switch (getCurveCoordinateSystem()) {
                case 0:
                    break;
                case 1:
                    ECFieldElement eCFieldElement3 = this.f678zs[0];
                    if (!eCFieldElement3.isOne()) {
                        ECFieldElement square2 = eCFieldElement3.square();
                        ECFieldElement multiply = eCFieldElement3.multiply(square2);
                        square = square.multiply(eCFieldElement3);
                        a = a.multiply(square2);
                        b = b.multiply(multiply);
                        break;
                    }
                    break;
                case 2:
                case 3:
                case 4:
                    ECFieldElement eCFieldElement4 = this.f678zs[0];
                    if (!eCFieldElement4.isOne()) {
                        ECFieldElement square3 = eCFieldElement4.square();
                        ECFieldElement square4 = square3.square();
                        ECFieldElement multiply2 = square3.multiply(square4);
                        a = a.multiply(square4);
                        b = b.multiply(multiply2);
                        break;
                    }
                    break;
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
            return square.equals(eCFieldElement.square().add(a).multiply(eCFieldElement).add(b));
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint subtract(ECPoint eCPoint) {
            return eCPoint.isInfinity() ? this : add(eCPoint.negate());
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECPoint$F2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECPoint$F2m.class */
    public static class F2m extends AbstractF2m {
        /* JADX INFO: Access modifiers changed from: package-private */
        public F2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public F2m(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected ECPoint detach() {
            return new F2m(null, getAffineXCoord(), getAffineYCoord());
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECFieldElement getYCoord() {
            int curveCoordinateSystem = getCurveCoordinateSystem();
            switch (curveCoordinateSystem) {
                case 5:
                case 6:
                    ECFieldElement eCFieldElement = this.f676x;
                    ECFieldElement eCFieldElement2 = this.f677y;
                    if (isInfinity() || eCFieldElement.isZero()) {
                        return eCFieldElement2;
                    }
                    ECFieldElement multiply = eCFieldElement2.add(eCFieldElement).multiply(eCFieldElement);
                    if (6 == curveCoordinateSystem) {
                        ECFieldElement eCFieldElement3 = this.f678zs[0];
                        if (!eCFieldElement3.isOne()) {
                            multiply = multiply.divide(eCFieldElement3);
                        }
                    }
                    return multiply;
                default:
                    return this.f677y;
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected boolean getCompressionYTilde() {
            ECFieldElement rawXCoord = getRawXCoord();
            if (rawXCoord.isZero()) {
                return false;
            }
            ECFieldElement rawYCoord = getRawYCoord();
            switch (getCurveCoordinateSystem()) {
                case 5:
                case 6:
                    return rawYCoord.testBitZero() != rawXCoord.testBitZero();
                default:
                    return rawYCoord.divide(rawXCoord).testBitZero();
            }
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
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement eCFieldElement2 = this.f676x;
            ECFieldElement eCFieldElement3 = eCPoint.f676x;
            switch (coordinateSystem) {
                case 0:
                    ECFieldElement eCFieldElement4 = this.f677y;
                    ECFieldElement eCFieldElement5 = eCPoint.f677y;
                    ECFieldElement add = eCFieldElement2.add(eCFieldElement3);
                    ECFieldElement add2 = eCFieldElement4.add(eCFieldElement5);
                    if (add.isZero()) {
                        return add2.isZero() ? twice() : curve.getInfinity();
                    }
                    ECFieldElement divide = add2.divide(add);
                    ECFieldElement add3 = divide.square().add(divide).add(add).add(curve.getA());
                    return new F2m(curve, add3, divide.multiply(eCFieldElement2.add(add3)).add(add3).add(eCFieldElement4));
                case 1:
                    ECFieldElement eCFieldElement6 = this.f677y;
                    ECFieldElement eCFieldElement7 = this.f678zs[0];
                    ECFieldElement eCFieldElement8 = eCPoint.f677y;
                    ECFieldElement eCFieldElement9 = eCPoint.f678zs[0];
                    boolean isOne = eCFieldElement9.isOne();
                    ECFieldElement add4 = eCFieldElement7.multiply(eCFieldElement8).add(isOne ? eCFieldElement6 : eCFieldElement6.multiply(eCFieldElement9));
                    ECFieldElement add5 = eCFieldElement7.multiply(eCFieldElement3).add(isOne ? eCFieldElement2 : eCFieldElement2.multiply(eCFieldElement9));
                    if (add5.isZero()) {
                        return add4.isZero() ? twice() : curve.getInfinity();
                    }
                    ECFieldElement square = add5.square();
                    ECFieldElement multiply2 = square.multiply(add5);
                    ECFieldElement multiply3 = isOne ? eCFieldElement7 : eCFieldElement7.multiply(eCFieldElement9);
                    ECFieldElement add6 = add4.add(add5);
                    ECFieldElement add7 = add6.multiplyPlusProduct(add4, square, curve.getA()).multiply(multiply3).add(multiply2);
                    return new F2m(curve, add5.multiply(add7), add4.multiplyPlusProduct(eCFieldElement2, add5, eCFieldElement6).multiplyPlusProduct(isOne ? square : square.multiply(eCFieldElement9), add6, add7), new ECFieldElement[]{multiply2.multiply(multiply3)});
                case 6:
                    if (eCFieldElement2.isZero()) {
                        return eCFieldElement3.isZero() ? curve.getInfinity() : eCPoint.add(this);
                    }
                    ECFieldElement eCFieldElement10 = this.f677y;
                    ECFieldElement eCFieldElement11 = this.f678zs[0];
                    ECFieldElement eCFieldElement12 = eCPoint.f677y;
                    ECFieldElement eCFieldElement13 = eCPoint.f678zs[0];
                    boolean isOne2 = eCFieldElement11.isOne();
                    ECFieldElement eCFieldElement14 = eCFieldElement3;
                    ECFieldElement eCFieldElement15 = eCFieldElement12;
                    if (!isOne2) {
                        eCFieldElement14 = eCFieldElement14.multiply(eCFieldElement11);
                        eCFieldElement15 = eCFieldElement15.multiply(eCFieldElement11);
                    }
                    boolean isOne3 = eCFieldElement13.isOne();
                    ECFieldElement eCFieldElement16 = eCFieldElement2;
                    ECFieldElement eCFieldElement17 = eCFieldElement10;
                    if (!isOne3) {
                        eCFieldElement16 = eCFieldElement16.multiply(eCFieldElement13);
                        eCFieldElement17 = eCFieldElement17.multiply(eCFieldElement13);
                    }
                    ECFieldElement add8 = eCFieldElement17.add(eCFieldElement15);
                    ECFieldElement add9 = eCFieldElement16.add(eCFieldElement14);
                    if (add9.isZero()) {
                        return add8.isZero() ? twice() : curve.getInfinity();
                    }
                    if (eCFieldElement3.isZero()) {
                        ECPoint normalize = normalize();
                        ECFieldElement xCoord = normalize.getXCoord();
                        ECFieldElement yCoord = normalize.getYCoord();
                        ECFieldElement divide2 = yCoord.add(eCFieldElement12).divide(xCoord);
                        multiply = divide2.square().add(divide2).add(xCoord).add(curve.getA());
                        if (multiply.isZero()) {
                            return new F2m(curve, multiply, curve.getB().sqrt());
                        }
                        squarePlusProduct = divide2.multiply(xCoord.add(multiply)).add(multiply).add(yCoord).divide(multiply).add(multiply);
                        eCFieldElement = curve.fromBigInteger(ECConstants.ONE);
                    } else {
                        ECFieldElement square2 = add9.square();
                        ECFieldElement multiply4 = add8.multiply(eCFieldElement16);
                        ECFieldElement multiply5 = add8.multiply(eCFieldElement14);
                        multiply = multiply4.multiply(multiply5);
                        if (multiply.isZero()) {
                            return new F2m(curve, multiply, curve.getB().sqrt());
                        }
                        ECFieldElement multiply6 = add8.multiply(square2);
                        if (!isOne3) {
                            multiply6 = multiply6.multiply(eCFieldElement13);
                        }
                        squarePlusProduct = multiply5.add(square2).squarePlusProduct(multiply6, eCFieldElement10.add(eCFieldElement11));
                        eCFieldElement = multiply6;
                        if (!isOne2) {
                            eCFieldElement = eCFieldElement.multiply(eCFieldElement11);
                        }
                    }
                    return new F2m(curve, multiply, squarePlusProduct, new ECFieldElement[]{eCFieldElement});
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint twice() {
            ECFieldElement add;
            if (isInfinity()) {
                return this;
            }
            ECCurve curve = getCurve();
            ECFieldElement eCFieldElement = this.f676x;
            if (eCFieldElement.isZero()) {
                return curve.getInfinity();
            }
            switch (curve.getCoordinateSystem()) {
                case 0:
                    ECFieldElement add2 = this.f677y.divide(eCFieldElement).add(eCFieldElement);
                    ECFieldElement add3 = add2.square().add(add2).add(curve.getA());
                    return new F2m(curve, add3, eCFieldElement.squarePlusProduct(add3, add2.addOne()));
                case 1:
                    ECFieldElement eCFieldElement2 = this.f677y;
                    ECFieldElement eCFieldElement3 = this.f678zs[0];
                    boolean isOne = eCFieldElement3.isOne();
                    ECFieldElement multiply = isOne ? eCFieldElement : eCFieldElement.multiply(eCFieldElement3);
                    ECFieldElement multiply2 = isOne ? eCFieldElement2 : eCFieldElement2.multiply(eCFieldElement3);
                    ECFieldElement square = eCFieldElement.square();
                    ECFieldElement add4 = square.add(multiply2);
                    ECFieldElement square2 = multiply.square();
                    ECFieldElement add5 = add4.add(multiply);
                    ECFieldElement multiplyPlusProduct = add5.multiplyPlusProduct(add4, square2, curve.getA());
                    return new F2m(curve, multiply.multiply(multiplyPlusProduct), square.square().multiplyPlusProduct(multiply, multiplyPlusProduct, add5), new ECFieldElement[]{multiply.multiply(square2)});
                case 6:
                    ECFieldElement eCFieldElement4 = this.f677y;
                    ECFieldElement eCFieldElement5 = this.f678zs[0];
                    boolean isOne2 = eCFieldElement5.isOne();
                    ECFieldElement multiply3 = isOne2 ? eCFieldElement4 : eCFieldElement4.multiply(eCFieldElement5);
                    ECFieldElement square3 = isOne2 ? eCFieldElement5 : eCFieldElement5.square();
                    ECFieldElement a = curve.getA();
                    ECFieldElement multiply4 = isOne2 ? a : a.multiply(square3);
                    ECFieldElement add6 = eCFieldElement4.square().add(multiply3).add(multiply4);
                    if (add6.isZero()) {
                        return new F2m(curve, add6, curve.getB().sqrt());
                    }
                    ECFieldElement square4 = add6.square();
                    ECFieldElement multiply5 = isOne2 ? add6 : add6.multiply(square3);
                    ECFieldElement b = curve.getB();
                    if (b.bitLength() < (curve.getFieldSize() >> 1)) {
                        ECFieldElement square5 = eCFieldElement4.add(eCFieldElement).square();
                        add = square5.add(add6).add(square3).multiply(square5).add(b.isOne() ? multiply4.add(square3).square() : multiply4.squarePlusProduct(b, square3.square())).add(square4);
                        if (a.isZero()) {
                            add = add.add(multiply5);
                        } else if (!a.isOne()) {
                            add = add.add(a.addOne().multiply(multiply5));
                        }
                    } else {
                        add = (isOne2 ? eCFieldElement : eCFieldElement.multiply(eCFieldElement5)).squarePlusProduct(add6, multiply3).add(square4).add(multiply5);
                    }
                    return new F2m(curve, square4, add, new ECFieldElement[]{multiply5});
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
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
            switch (curve.getCoordinateSystem()) {
                case 6:
                    ECFieldElement eCFieldElement2 = eCPoint.f676x;
                    ECFieldElement eCFieldElement3 = eCPoint.f678zs[0];
                    if (eCFieldElement2.isZero() || !eCFieldElement3.isOne()) {
                        return twice().add(eCPoint);
                    }
                    ECFieldElement eCFieldElement4 = this.f677y;
                    ECFieldElement eCFieldElement5 = this.f678zs[0];
                    ECFieldElement eCFieldElement6 = eCPoint.f677y;
                    ECFieldElement square = eCFieldElement.square();
                    ECFieldElement square2 = eCFieldElement4.square();
                    ECFieldElement square3 = eCFieldElement5.square();
                    ECFieldElement add = curve.getA().multiply(square3).add(square2).add(eCFieldElement4.multiply(eCFieldElement5));
                    ECFieldElement addOne = eCFieldElement6.addOne();
                    ECFieldElement multiplyPlusProduct = curve.getA().add(addOne).multiply(square3).add(square2).multiplyPlusProduct(add, square, square3);
                    ECFieldElement multiply = eCFieldElement2.multiply(square3);
                    ECFieldElement square4 = multiply.add(add).square();
                    if (square4.isZero()) {
                        return multiplyPlusProduct.isZero() ? eCPoint.twice() : curve.getInfinity();
                    } else if (multiplyPlusProduct.isZero()) {
                        return new F2m(curve, multiplyPlusProduct, curve.getB().sqrt());
                    } else {
                        ECFieldElement multiply2 = multiplyPlusProduct.square().multiply(multiply);
                        ECFieldElement multiply3 = multiplyPlusProduct.multiply(square4).multiply(square3);
                        return new F2m(curve, multiply2, multiplyPlusProduct.add(square4).square().multiplyPlusProduct(add, addOne, multiply3), new ECFieldElement[]{multiply3});
                    }
                default:
                    return twice().add(eCPoint);
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
            switch (getCurveCoordinateSystem()) {
                case 0:
                    return new F2m(this.curve, eCFieldElement, this.f677y.add(eCFieldElement));
                case 1:
                    return new F2m(this.curve, eCFieldElement, this.f677y.add(eCFieldElement), new ECFieldElement[]{this.f678zs[0]});
                case 2:
                case 3:
                case 4:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
                case 5:
                    return new F2m(this.curve, eCFieldElement, this.f677y.addOne());
                case 6:
                    ECFieldElement eCFieldElement2 = this.f677y;
                    ECFieldElement eCFieldElement3 = this.f678zs[0];
                    return new F2m(this.curve, eCFieldElement, eCFieldElement2.add(eCFieldElement3), new ECFieldElement[]{eCFieldElement3});
            }
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECPoint$Fp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECPoint$Fp.class */
    public static class C0280Fp extends AbstractFp {
        /* JADX INFO: Access modifiers changed from: package-private */
        public C0280Fp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            super(eCCurve, eCFieldElement, eCFieldElement2);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public C0280Fp(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
            super(eCCurve, eCFieldElement, eCFieldElement2, eCFieldElementArr);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        protected ECPoint detach() {
            return new C0280Fp(null, getAffineXCoord(), getAffineYCoord());
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECFieldElement getZCoord(int i) {
            return (i == 1 && 4 == getCurveCoordinateSystem()) ? getJacobianModifiedW() : super.getZCoord(i);
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint add(ECPoint eCPoint) {
            ECFieldElement multiply;
            ECFieldElement multiply2;
            ECFieldElement multiply3;
            ECFieldElement multiply4;
            ECFieldElement subtract;
            ECFieldElement multiplyMinusProduct;
            ECFieldElement eCFieldElement;
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
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement eCFieldElement2 = this.f676x;
            ECFieldElement eCFieldElement3 = this.f677y;
            ECFieldElement eCFieldElement4 = eCPoint.f676x;
            ECFieldElement eCFieldElement5 = eCPoint.f677y;
            switch (coordinateSystem) {
                case 0:
                    ECFieldElement subtract2 = eCFieldElement4.subtract(eCFieldElement2);
                    ECFieldElement subtract3 = eCFieldElement5.subtract(eCFieldElement3);
                    if (subtract2.isZero()) {
                        return subtract3.isZero() ? twice() : curve.getInfinity();
                    }
                    ECFieldElement divide = subtract3.divide(subtract2);
                    ECFieldElement subtract4 = divide.square().subtract(eCFieldElement2).subtract(eCFieldElement4);
                    return new C0280Fp(curve, subtract4, divide.multiply(eCFieldElement2.subtract(subtract4)).subtract(eCFieldElement3));
                case 1:
                    ECFieldElement eCFieldElement6 = this.f678zs[0];
                    ECFieldElement eCFieldElement7 = eCPoint.f678zs[0];
                    boolean isOne = eCFieldElement6.isOne();
                    boolean isOne2 = eCFieldElement7.isOne();
                    ECFieldElement multiply5 = isOne ? eCFieldElement5 : eCFieldElement5.multiply(eCFieldElement6);
                    ECFieldElement multiply6 = isOne2 ? eCFieldElement3 : eCFieldElement3.multiply(eCFieldElement7);
                    ECFieldElement subtract5 = multiply5.subtract(multiply6);
                    ECFieldElement multiply7 = isOne ? eCFieldElement4 : eCFieldElement4.multiply(eCFieldElement6);
                    ECFieldElement multiply8 = isOne2 ? eCFieldElement2 : eCFieldElement2.multiply(eCFieldElement7);
                    ECFieldElement subtract6 = multiply7.subtract(multiply8);
                    if (subtract6.isZero()) {
                        return subtract5.isZero() ? twice() : curve.getInfinity();
                    }
                    ECFieldElement multiply9 = isOne ? eCFieldElement7 : isOne2 ? eCFieldElement6 : eCFieldElement6.multiply(eCFieldElement7);
                    ECFieldElement square = subtract6.square();
                    ECFieldElement multiply10 = square.multiply(subtract6);
                    ECFieldElement multiply11 = square.multiply(multiply8);
                    ECFieldElement subtract7 = subtract5.square().multiply(multiply9).subtract(multiply10).subtract(two(multiply11));
                    return new C0280Fp(curve, subtract6.multiply(subtract7), multiply11.subtract(subtract7).multiplyMinusProduct(subtract5, multiply6, multiply10), new ECFieldElement[]{multiply10.multiply(multiply9)});
                case 2:
                case 4:
                    ECFieldElement eCFieldElement8 = this.f678zs[0];
                    ECFieldElement eCFieldElement9 = eCPoint.f678zs[0];
                    boolean isOne3 = eCFieldElement8.isOne();
                    ECFieldElement eCFieldElement10 = null;
                    if (isOne3 || !eCFieldElement8.equals(eCFieldElement9)) {
                        if (isOne3) {
                            multiply = eCFieldElement4;
                            multiply2 = eCFieldElement5;
                        } else {
                            ECFieldElement square2 = eCFieldElement8.square();
                            multiply = square2.multiply(eCFieldElement4);
                            multiply2 = square2.multiply(eCFieldElement8).multiply(eCFieldElement5);
                        }
                        boolean isOne4 = eCFieldElement9.isOne();
                        if (isOne4) {
                            multiply3 = eCFieldElement2;
                            multiply4 = eCFieldElement3;
                        } else {
                            ECFieldElement square3 = eCFieldElement9.square();
                            multiply3 = square3.multiply(eCFieldElement2);
                            multiply4 = square3.multiply(eCFieldElement9).multiply(eCFieldElement3);
                        }
                        ECFieldElement subtract8 = multiply3.subtract(multiply);
                        ECFieldElement subtract9 = multiply4.subtract(multiply2);
                        if (subtract8.isZero()) {
                            return subtract9.isZero() ? twice() : curve.getInfinity();
                        }
                        ECFieldElement square4 = subtract8.square();
                        ECFieldElement multiply12 = square4.multiply(subtract8);
                        ECFieldElement multiply13 = square4.multiply(multiply3);
                        subtract = subtract9.square().add(multiply12).subtract(two(multiply13));
                        multiplyMinusProduct = multiply13.subtract(subtract).multiplyMinusProduct(subtract9, multiply12, multiply4);
                        eCFieldElement = subtract8;
                        if (!isOne3) {
                            eCFieldElement = eCFieldElement.multiply(eCFieldElement8);
                        }
                        if (!isOne4) {
                            eCFieldElement = eCFieldElement.multiply(eCFieldElement9);
                        }
                        if (eCFieldElement == subtract8) {
                            eCFieldElement10 = square4;
                        }
                    } else {
                        ECFieldElement subtract10 = eCFieldElement2.subtract(eCFieldElement4);
                        ECFieldElement subtract11 = eCFieldElement3.subtract(eCFieldElement5);
                        if (subtract10.isZero()) {
                            return subtract11.isZero() ? twice() : curve.getInfinity();
                        }
                        ECFieldElement square5 = subtract10.square();
                        ECFieldElement multiply14 = eCFieldElement2.multiply(square5);
                        ECFieldElement multiply15 = eCFieldElement4.multiply(square5);
                        ECFieldElement multiply16 = multiply14.subtract(multiply15).multiply(eCFieldElement3);
                        subtract = subtract11.square().subtract(multiply14).subtract(multiply15);
                        multiplyMinusProduct = multiply14.subtract(subtract).multiply(subtract11).subtract(multiply16);
                        eCFieldElement = subtract10.multiply(eCFieldElement8);
                    }
                    return new C0280Fp(curve, subtract, multiplyMinusProduct, coordinateSystem == 4 ? new ECFieldElement[]{eCFieldElement, calculateJacobianModifiedW(eCFieldElement, eCFieldElement10)} : new ECFieldElement[]{eCFieldElement});
                case 3:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint twice() {
            ECFieldElement three;
            ECFieldElement four;
            if (isInfinity()) {
                return this;
            }
            ECCurve curve = getCurve();
            ECFieldElement eCFieldElement = this.f677y;
            if (eCFieldElement.isZero()) {
                return curve.getInfinity();
            }
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement eCFieldElement2 = this.f676x;
            switch (coordinateSystem) {
                case 0:
                    ECFieldElement divide = three(eCFieldElement2.square()).add(getCurve().getA()).divide(two(eCFieldElement));
                    ECFieldElement subtract = divide.square().subtract(two(eCFieldElement2));
                    return new C0280Fp(curve, subtract, divide.multiply(eCFieldElement2.subtract(subtract)).subtract(eCFieldElement));
                case 1:
                    ECFieldElement eCFieldElement3 = this.f678zs[0];
                    boolean isOne = eCFieldElement3.isOne();
                    ECFieldElement a = curve.getA();
                    if (!a.isZero() && !isOne) {
                        a = a.multiply(eCFieldElement3.square());
                    }
                    ECFieldElement add = a.add(three(eCFieldElement2.square()));
                    ECFieldElement multiply = isOne ? eCFieldElement : eCFieldElement.multiply(eCFieldElement3);
                    ECFieldElement square = isOne ? eCFieldElement.square() : multiply.multiply(eCFieldElement);
                    ECFieldElement four2 = four(eCFieldElement2.multiply(square));
                    ECFieldElement subtract2 = add.square().subtract(two(four2));
                    ECFieldElement two = two(multiply);
                    ECFieldElement multiply2 = subtract2.multiply(two);
                    ECFieldElement two2 = two(square);
                    return new C0280Fp(curve, multiply2, four2.subtract(subtract2).multiply(add).subtract(two(two2.square())), new ECFieldElement[]{two(isOne ? two(two2) : two.square()).multiply(multiply)});
                case 2:
                    ECFieldElement eCFieldElement4 = this.f678zs[0];
                    boolean isOne2 = eCFieldElement4.isOne();
                    ECFieldElement square2 = eCFieldElement.square();
                    ECFieldElement square3 = square2.square();
                    ECFieldElement a2 = curve.getA();
                    ECFieldElement negate = a2.negate();
                    if (negate.toBigInteger().equals(BigInteger.valueOf(3L))) {
                        ECFieldElement square4 = isOne2 ? eCFieldElement4 : eCFieldElement4.square();
                        three = three(eCFieldElement2.add(square4).multiply(eCFieldElement2.subtract(square4)));
                        four = four(square2.multiply(eCFieldElement2));
                    } else {
                        three = three(eCFieldElement2.square());
                        if (isOne2) {
                            three = three.add(a2);
                        } else if (!a2.isZero()) {
                            ECFieldElement square5 = eCFieldElement4.square().square();
                            three = negate.bitLength() < a2.bitLength() ? three.subtract(square5.multiply(negate)) : three.add(square5.multiply(a2));
                        }
                        four = four(eCFieldElement2.multiply(square2));
                    }
                    ECFieldElement subtract3 = three.square().subtract(two(four));
                    ECFieldElement subtract4 = four.subtract(subtract3).multiply(three).subtract(eight(square3));
                    ECFieldElement two3 = two(eCFieldElement);
                    if (!isOne2) {
                        two3 = two3.multiply(eCFieldElement4);
                    }
                    return new C0280Fp(curve, subtract3, subtract4, new ECFieldElement[]{two3});
                case 3:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
                case 4:
                    return twiceJacobianModified(true);
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint twicePlus(ECPoint eCPoint) {
            if (this == eCPoint) {
                return threeTimes();
            }
            if (isInfinity()) {
                return eCPoint;
            }
            if (eCPoint.isInfinity()) {
                return twice();
            }
            ECFieldElement eCFieldElement = this.f677y;
            if (eCFieldElement.isZero()) {
                return eCPoint;
            }
            ECCurve curve = getCurve();
            switch (curve.getCoordinateSystem()) {
                case 0:
                    ECFieldElement eCFieldElement2 = this.f676x;
                    ECFieldElement eCFieldElement3 = eCPoint.f676x;
                    ECFieldElement eCFieldElement4 = eCPoint.f677y;
                    ECFieldElement subtract = eCFieldElement3.subtract(eCFieldElement2);
                    ECFieldElement subtract2 = eCFieldElement4.subtract(eCFieldElement);
                    if (subtract.isZero()) {
                        return subtract2.isZero() ? threeTimes() : this;
                    }
                    ECFieldElement square = subtract.square();
                    ECFieldElement subtract3 = square.multiply(two(eCFieldElement2).add(eCFieldElement3)).subtract(subtract2.square());
                    if (subtract3.isZero()) {
                        return curve.getInfinity();
                    }
                    ECFieldElement invert = subtract3.multiply(subtract).invert();
                    ECFieldElement multiply = subtract3.multiply(invert).multiply(subtract2);
                    ECFieldElement subtract4 = two(eCFieldElement).multiply(square).multiply(subtract).multiply(invert).subtract(multiply);
                    ECFieldElement add = subtract4.subtract(multiply).multiply(multiply.add(subtract4)).add(eCFieldElement3);
                    return new C0280Fp(curve, add, eCFieldElement2.subtract(add).multiply(subtract4).subtract(eCFieldElement));
                case 4:
                    return twiceJacobianModified(false).add(eCPoint);
                default:
                    return twice().add(eCPoint);
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint threeTimes() {
            if (isInfinity()) {
                return this;
            }
            ECFieldElement eCFieldElement = this.f677y;
            if (eCFieldElement.isZero()) {
                return this;
            }
            ECCurve curve = getCurve();
            switch (curve.getCoordinateSystem()) {
                case 0:
                    ECFieldElement eCFieldElement2 = this.f676x;
                    ECFieldElement two = two(eCFieldElement);
                    ECFieldElement square = two.square();
                    ECFieldElement add = three(eCFieldElement2.square()).add(getCurve().getA());
                    ECFieldElement subtract = three(eCFieldElement2).multiply(square).subtract(add.square());
                    if (subtract.isZero()) {
                        return getCurve().getInfinity();
                    }
                    ECFieldElement invert = subtract.multiply(two).invert();
                    ECFieldElement multiply = subtract.multiply(invert).multiply(add);
                    ECFieldElement subtract2 = square.square().multiply(invert).subtract(multiply);
                    ECFieldElement add2 = subtract2.subtract(multiply).multiply(multiply.add(subtract2)).add(eCFieldElement2);
                    return new C0280Fp(curve, add2, eCFieldElement2.subtract(add2).multiply(subtract2).subtract(eCFieldElement));
                case 4:
                    return twiceJacobianModified(false).add(this);
                default:
                    return twice().add(this);
            }
        }

        @Override // org.bouncycastle.math.p010ec.ECPoint
        public ECPoint timesPow2(int i) {
            if (i < 0) {
                throw new IllegalArgumentException("'e' cannot be negative");
            }
            if (i == 0 || isInfinity()) {
                return this;
            }
            if (i == 1) {
                return twice();
            }
            ECCurve curve = getCurve();
            ECFieldElement eCFieldElement = this.f677y;
            if (eCFieldElement.isZero()) {
                return curve.getInfinity();
            }
            int coordinateSystem = curve.getCoordinateSystem();
            ECFieldElement a = curve.getA();
            ECFieldElement eCFieldElement2 = this.f676x;
            ECFieldElement fromBigInteger = this.f678zs.length < 1 ? curve.fromBigInteger(ECConstants.ONE) : this.f678zs[0];
            if (!fromBigInteger.isOne()) {
                switch (coordinateSystem) {
                    case 0:
                        break;
                    case 1:
                        ECFieldElement square = fromBigInteger.square();
                        eCFieldElement2 = eCFieldElement2.multiply(fromBigInteger);
                        eCFieldElement = eCFieldElement.multiply(square);
                        a = calculateJacobianModifiedW(fromBigInteger, square);
                        break;
                    case 2:
                        a = calculateJacobianModifiedW(fromBigInteger, null);
                        break;
                    case 3:
                    default:
                        throw new IllegalStateException("unsupported coordinate system");
                    case 4:
                        a = getJacobianModifiedW();
                        break;
                }
            }
            for (int i2 = 0; i2 < i; i2++) {
                if (eCFieldElement.isZero()) {
                    return curve.getInfinity();
                }
                ECFieldElement three = three(eCFieldElement2.square());
                ECFieldElement two = two(eCFieldElement);
                ECFieldElement multiply = two.multiply(eCFieldElement);
                ECFieldElement two2 = two(eCFieldElement2.multiply(multiply));
                ECFieldElement two3 = two(multiply.square());
                if (!a.isZero()) {
                    three = three.add(a);
                    a = two(two3.multiply(a));
                }
                eCFieldElement2 = three.square().subtract(two(two2));
                eCFieldElement = three.multiply(two2.subtract(eCFieldElement2)).subtract(two3);
                fromBigInteger = fromBigInteger.isOne() ? two : two.multiply(fromBigInteger);
            }
            switch (coordinateSystem) {
                case 0:
                    ECFieldElement invert = fromBigInteger.invert();
                    ECFieldElement square2 = invert.square();
                    return new C0280Fp(curve, eCFieldElement2.multiply(square2), eCFieldElement.multiply(square2.multiply(invert)));
                case 1:
                    return new C0280Fp(curve, eCFieldElement2.multiply(fromBigInteger), eCFieldElement, new ECFieldElement[]{fromBigInteger.multiply(fromBigInteger.square())});
                case 2:
                    return new C0280Fp(curve, eCFieldElement2, eCFieldElement, new ECFieldElement[]{fromBigInteger});
                case 3:
                default:
                    throw new IllegalStateException("unsupported coordinate system");
                case 4:
                    return new C0280Fp(curve, eCFieldElement2, eCFieldElement, new ECFieldElement[]{fromBigInteger, a});
            }
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
            if (isInfinity()) {
                return this;
            }
            ECCurve curve = getCurve();
            return 0 != curve.getCoordinateSystem() ? new C0280Fp(curve, this.f676x, this.f677y.negate(), this.f678zs) : new C0280Fp(curve, this.f676x, this.f677y.negate());
        }

        protected ECFieldElement calculateJacobianModifiedW(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            ECFieldElement a = getCurve().getA();
            if (a.isZero() || eCFieldElement.isOne()) {
                return a;
            }
            if (eCFieldElement2 == null) {
                eCFieldElement2 = eCFieldElement.square();
            }
            ECFieldElement square = eCFieldElement2.square();
            ECFieldElement negate = a.negate();
            return negate.bitLength() < a.bitLength() ? square.multiply(negate).negate() : square.multiply(a);
        }

        protected ECFieldElement getJacobianModifiedW() {
            ECFieldElement eCFieldElement = this.f678zs[1];
            if (eCFieldElement == null) {
                ECFieldElement[] eCFieldElementArr = this.f678zs;
                ECFieldElement calculateJacobianModifiedW = calculateJacobianModifiedW(this.f678zs[0], null);
                eCFieldElement = calculateJacobianModifiedW;
                eCFieldElementArr[1] = calculateJacobianModifiedW;
            }
            return eCFieldElement;
        }

        protected C0280Fp twiceJacobianModified(boolean z) {
            ECFieldElement eCFieldElement = this.f676x;
            ECFieldElement eCFieldElement2 = this.f677y;
            ECFieldElement eCFieldElement3 = this.f678zs[0];
            ECFieldElement jacobianModifiedW = getJacobianModifiedW();
            ECFieldElement add = three(eCFieldElement.square()).add(jacobianModifiedW);
            ECFieldElement two = two(eCFieldElement2);
            ECFieldElement multiply = two.multiply(eCFieldElement2);
            ECFieldElement two2 = two(eCFieldElement.multiply(multiply));
            ECFieldElement subtract = add.square().subtract(two(two2));
            ECFieldElement two3 = two(multiply.square());
            return new C0280Fp(getCurve(), subtract, add.multiply(two2.subtract(subtract)).subtract(two3), new ECFieldElement[]{eCFieldElement3.isOne() ? two : two.multiply(eCFieldElement3), z ? two(two3.multiply(jacobianModifiedW)) : null});
        }
    }

    protected static ECFieldElement[] getInitialZCoords(ECCurve eCCurve) {
        int coordinateSystem = null == eCCurve ? 0 : eCCurve.getCoordinateSystem();
        switch (coordinateSystem) {
            case 0:
            case 5:
                return EMPTY_ZS;
            default:
                ECFieldElement fromBigInteger = eCCurve.fromBigInteger(ECConstants.ONE);
                switch (coordinateSystem) {
                    case 1:
                    case 2:
                    case 6:
                        return new ECFieldElement[]{fromBigInteger};
                    case 3:
                        return new ECFieldElement[]{fromBigInteger, fromBigInteger, fromBigInteger};
                    case 4:
                        return new ECFieldElement[]{fromBigInteger, eCCurve.getA()};
                    case 5:
                    default:
                        throw new IllegalArgumentException("unknown coordinate system");
                }
        }
    }

    protected ECPoint(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        this(eCCurve, eCFieldElement, eCFieldElement2, getInitialZCoords(eCCurve));
    }

    protected ECPoint(ECCurve eCCurve, ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement[] eCFieldElementArr) {
        this.preCompTable = null;
        this.curve = eCCurve;
        this.f676x = eCFieldElement;
        this.f677y = eCFieldElement2;
        this.f678zs = eCFieldElementArr;
    }

    protected abstract boolean satisfiesCurveEquation();

    protected boolean satisfiesOrder() {
        BigInteger order;
        return ECConstants.ONE.equals(this.curve.getCofactor()) || (order = this.curve.getOrder()) == null || ECAlgorithms.referenceMultiply(this, order).isInfinity();
    }

    public final ECPoint getDetachedPoint() {
        return normalize().detach();
    }

    public ECCurve getCurve() {
        return this.curve;
    }

    protected abstract ECPoint detach();

    protected int getCurveCoordinateSystem() {
        if (null == this.curve) {
            return 0;
        }
        return this.curve.getCoordinateSystem();
    }

    public ECFieldElement getAffineXCoord() {
        checkNormalized();
        return getXCoord();
    }

    public ECFieldElement getAffineYCoord() {
        checkNormalized();
        return getYCoord();
    }

    public ECFieldElement getXCoord() {
        return this.f676x;
    }

    public ECFieldElement getYCoord() {
        return this.f677y;
    }

    public ECFieldElement getZCoord(int i) {
        if (i < 0 || i >= this.f678zs.length) {
            return null;
        }
        return this.f678zs[i];
    }

    public ECFieldElement[] getZCoords() {
        int length = this.f678zs.length;
        if (length == 0) {
            return EMPTY_ZS;
        }
        ECFieldElement[] eCFieldElementArr = new ECFieldElement[length];
        System.arraycopy(this.f678zs, 0, eCFieldElementArr, 0, length);
        return eCFieldElementArr;
    }

    public final ECFieldElement getRawXCoord() {
        return this.f676x;
    }

    public final ECFieldElement getRawYCoord() {
        return this.f677y;
    }

    protected final ECFieldElement[] getRawZCoords() {
        return this.f678zs;
    }

    protected void checkNormalized() {
        if (!isNormalized()) {
            throw new IllegalStateException("point not in normal form");
        }
    }

    public boolean isNormalized() {
        int curveCoordinateSystem = getCurveCoordinateSystem();
        return curveCoordinateSystem == 0 || curveCoordinateSystem == 5 || isInfinity() || this.f678zs[0].isOne();
    }

    public ECPoint normalize() {
        if (isInfinity()) {
            return this;
        }
        switch (getCurveCoordinateSystem()) {
            case 0:
            case 5:
                return this;
            default:
                ECFieldElement zCoord = getZCoord(0);
                if (zCoord.isOne()) {
                    return this;
                }
                if (null == this.curve) {
                    throw new IllegalStateException("Detached points must be in affine coordinates");
                }
                ECFieldElement randomFieldElementMult = this.curve.randomFieldElementMult(CryptoServicesRegistrar.getSecureRandom());
                return normalize(zCoord.multiply(randomFieldElementMult).invert().multiply(randomFieldElementMult));
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ECPoint normalize(ECFieldElement eCFieldElement) {
        switch (getCurveCoordinateSystem()) {
            case 1:
            case 6:
                return createScaledPoint(eCFieldElement, eCFieldElement);
            case 2:
            case 3:
            case 4:
                ECFieldElement square = eCFieldElement.square();
                return createScaledPoint(square, square.multiply(eCFieldElement));
            case 5:
            default:
                throw new IllegalStateException("not a projective coordinate system");
        }
    }

    protected ECPoint createScaledPoint(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return getCurve().createRawPoint(getRawXCoord().multiply(eCFieldElement), getRawYCoord().multiply(eCFieldElement2));
    }

    public boolean isInfinity() {
        return this.f676x == null || this.f677y == null || (this.f678zs.length > 0 && this.f678zs[0].isZero());
    }

    public boolean isValid() {
        return implIsValid(false, true);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isValidPartial() {
        return implIsValid(false, false);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean implIsValid(final boolean z, final boolean z2) {
        return isInfinity() || !((ValidityPrecompInfo) getCurve().precompute(this, "bc_validity", new PreCompCallback() { // from class: org.bouncycastle.math.ec.ECPoint.1
            @Override // org.bouncycastle.math.p010ec.PreCompCallback
            public PreCompInfo precompute(PreCompInfo preCompInfo) {
                ValidityPrecompInfo validityPrecompInfo = preCompInfo instanceof ValidityPrecompInfo ? (ValidityPrecompInfo) preCompInfo : null;
                if (validityPrecompInfo == null) {
                    validityPrecompInfo = new ValidityPrecompInfo();
                }
                if (validityPrecompInfo.hasFailed()) {
                    return validityPrecompInfo;
                }
                if (!validityPrecompInfo.hasCurveEquationPassed()) {
                    if (!z && !ECPoint.this.satisfiesCurveEquation()) {
                        validityPrecompInfo.reportFailed();
                        return validityPrecompInfo;
                    }
                    validityPrecompInfo.reportCurveEquationPassed();
                }
                if (z2 && !validityPrecompInfo.hasOrderPassed()) {
                    if (!ECPoint.this.satisfiesOrder()) {
                        validityPrecompInfo.reportFailed();
                        return validityPrecompInfo;
                    }
                    validityPrecompInfo.reportOrderPassed();
                }
                return validityPrecompInfo;
            }
        })).hasFailed();
    }

    public ECPoint scaleX(ECFieldElement eCFieldElement) {
        return isInfinity() ? this : getCurve().createRawPoint(getRawXCoord().multiply(eCFieldElement), getRawYCoord(), getRawZCoords());
    }

    public ECPoint scaleXNegateY(ECFieldElement eCFieldElement) {
        return isInfinity() ? this : getCurve().createRawPoint(getRawXCoord().multiply(eCFieldElement), getRawYCoord().negate(), getRawZCoords());
    }

    public ECPoint scaleY(ECFieldElement eCFieldElement) {
        return isInfinity() ? this : getCurve().createRawPoint(getRawXCoord(), getRawYCoord().multiply(eCFieldElement), getRawZCoords());
    }

    public ECPoint scaleYNegateX(ECFieldElement eCFieldElement) {
        return isInfinity() ? this : getCurve().createRawPoint(getRawXCoord().negate(), getRawYCoord().multiply(eCFieldElement), getRawZCoords());
    }

    public boolean equals(ECPoint eCPoint) {
        if (null == eCPoint) {
            return false;
        }
        ECCurve curve = getCurve();
        ECCurve curve2 = eCPoint.getCurve();
        boolean z = null == curve;
        boolean z2 = null == curve2;
        boolean isInfinity = isInfinity();
        boolean isInfinity2 = eCPoint.isInfinity();
        if (isInfinity || isInfinity2) {
            return isInfinity && isInfinity2 && (z || z2 || curve.equals(curve2));
        }
        ECPoint eCPoint2 = this;
        ECPoint eCPoint3 = eCPoint;
        if (!z || !z2) {
            if (z) {
                eCPoint3 = eCPoint3.normalize();
            } else if (z2) {
                eCPoint2 = eCPoint2.normalize();
            } else if (!curve.equals(curve2)) {
                return false;
            } else {
                ECPoint[] eCPointArr = {this, curve.importPoint(eCPoint3)};
                curve.normalizeAll(eCPointArr);
                eCPoint2 = eCPointArr[0];
                eCPoint3 = eCPointArr[1];
            }
        }
        return eCPoint2.getXCoord().equals(eCPoint3.getXCoord()) && eCPoint2.getYCoord().equals(eCPoint3.getYCoord());
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof ECPoint) {
            return equals((ECPoint) obj);
        }
        return false;
    }

    public int hashCode() {
        ECCurve curve = getCurve();
        int hashCode = null == curve ? 0 : curve.hashCode() ^ (-1);
        if (!isInfinity()) {
            ECPoint normalize = normalize();
            hashCode = (hashCode ^ (normalize.getXCoord().hashCode() * 17)) ^ (normalize.getYCoord().hashCode() * 257);
        }
        return hashCode;
    }

    public String toString() {
        if (isInfinity()) {
            return "INF";
        }
        StringBuffer stringBuffer = new StringBuffer();
        stringBuffer.append('(');
        stringBuffer.append(getRawXCoord());
        stringBuffer.append(',');
        stringBuffer.append(getRawYCoord());
        for (int i = 0; i < this.f678zs.length; i++) {
            stringBuffer.append(',');
            stringBuffer.append(this.f678zs[i]);
        }
        stringBuffer.append(')');
        return stringBuffer.toString();
    }

    public byte[] getEncoded(boolean z) {
        if (isInfinity()) {
            return new byte[1];
        }
        ECPoint normalize = normalize();
        byte[] encoded = normalize.getXCoord().getEncoded();
        if (z) {
            byte[] bArr = new byte[encoded.length + 1];
            bArr[0] = (byte) (normalize.getCompressionYTilde() ? 3 : 2);
            System.arraycopy(encoded, 0, bArr, 1, encoded.length);
            return bArr;
        }
        byte[] encoded2 = normalize.getYCoord().getEncoded();
        byte[] bArr2 = new byte[encoded.length + encoded2.length + 1];
        bArr2[0] = 4;
        System.arraycopy(encoded, 0, bArr2, 1, encoded.length);
        System.arraycopy(encoded2, 0, bArr2, encoded.length + 1, encoded2.length);
        return bArr2;
    }

    protected abstract boolean getCompressionYTilde();

    public abstract ECPoint add(ECPoint eCPoint);

    public abstract ECPoint negate();

    public abstract ECPoint subtract(ECPoint eCPoint);

    public ECPoint timesPow2(int i) {
        if (i < 0) {
            throw new IllegalArgumentException("'e' cannot be negative");
        }
        ECPoint eCPoint = this;
        while (true) {
            ECPoint eCPoint2 = eCPoint;
            i--;
            if (i < 0) {
                return eCPoint2;
            }
            eCPoint = eCPoint2.twice();
        }
    }

    public abstract ECPoint twice();

    public ECPoint twicePlus(ECPoint eCPoint) {
        return twice().add(eCPoint);
    }

    public ECPoint threeTimes() {
        return twicePlus(this);
    }

    public ECPoint multiply(BigInteger bigInteger) {
        return getCurve().getMultiplier().multiply(this, bigInteger);
    }
}