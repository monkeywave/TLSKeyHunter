package org.bouncycastle.math.p010ec;

import java.math.BigInteger;
import java.util.Random;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

/* renamed from: org.bouncycastle.math.ec.ECFieldElement */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECFieldElement.class */
public abstract class ECFieldElement implements ECConstants {

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$AbstractF2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECFieldElement$AbstractF2m.class */
    public static abstract class AbstractF2m extends ECFieldElement {
        public ECFieldElement halfTrace() {
            int fieldSize = getFieldSize();
            if ((fieldSize & 1) == 0) {
                throw new IllegalStateException("Half-trace only defined for odd m");
            }
            int i = (fieldSize + 1) >>> 1;
            int numberOfLeadingZeros = 31 - Integers.numberOfLeadingZeros(i);
            int i2 = 1;
            ECFieldElement eCFieldElement = this;
            while (numberOfLeadingZeros > 0) {
                eCFieldElement = eCFieldElement.squarePow(i2 << 1).add(eCFieldElement);
                numberOfLeadingZeros--;
                i2 = i >>> numberOfLeadingZeros;
                if (0 != (i2 & 1)) {
                    eCFieldElement = eCFieldElement.squarePow(2).add(this);
                }
            }
            return eCFieldElement;
        }

        public boolean hasFastTrace() {
            return false;
        }

        public int trace() {
            int fieldSize = getFieldSize();
            int numberOfLeadingZeros = 31 - Integers.numberOfLeadingZeros(fieldSize);
            int i = 1;
            ECFieldElement eCFieldElement = this;
            while (numberOfLeadingZeros > 0) {
                eCFieldElement = eCFieldElement.squarePow(i).add(eCFieldElement);
                numberOfLeadingZeros--;
                i = fieldSize >>> numberOfLeadingZeros;
                if (0 != (i & 1)) {
                    eCFieldElement = eCFieldElement.square().add(this);
                }
            }
            if (eCFieldElement.isZero()) {
                return 0;
            }
            if (eCFieldElement.isOne()) {
                return 1;
            }
            throw new IllegalStateException("Internal error in trace calculation");
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$AbstractFp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECFieldElement$AbstractFp.class */
    public static abstract class AbstractFp extends ECFieldElement {
    }

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$F2m */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECFieldElement$F2m.class */
    public static class F2m extends AbstractF2m {
        public static final int GNB = 1;
        public static final int TPB = 2;
        public static final int PPB = 3;
        private int representation;

        /* renamed from: m */
        private int f670m;

        /* renamed from: ks */
        private int[] f671ks;

        /* renamed from: x */
        LongArray f672x;

        /* JADX INFO: Access modifiers changed from: package-private */
        public F2m(int i, int i2, int i3, int i4, BigInteger bigInteger) {
            if (bigInteger == null || bigInteger.signum() < 0 || bigInteger.bitLength() > i) {
                throw new IllegalArgumentException("x value invalid in F2m field element");
            }
            if (i3 == 0 && i4 == 0) {
                this.representation = 2;
                this.f671ks = new int[]{i2};
            } else if (i3 >= i4) {
                throw new IllegalArgumentException("k2 must be smaller than k3");
            } else {
                if (i3 <= 0) {
                    throw new IllegalArgumentException("k2 must be larger than 0");
                }
                this.representation = 3;
                this.f671ks = new int[]{i2, i3, i4};
            }
            this.f670m = i;
            this.f672x = new LongArray(bigInteger);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public F2m(int i, int[] iArr, LongArray longArray) {
            this.f670m = i;
            this.representation = iArr.length == 1 ? 2 : 3;
            this.f671ks = iArr;
            this.f672x = longArray;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public int bitLength() {
            return this.f672x.degree();
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public boolean isOne() {
            return this.f672x.isOne();
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public boolean isZero() {
            return this.f672x.isZero();
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public boolean testBitZero() {
            return this.f672x.testBitZero();
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public BigInteger toBigInteger() {
            return this.f672x.toBigInteger();
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public String getFieldName() {
            return "F2m";
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public int getFieldSize() {
            return this.f670m;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement add(ECFieldElement eCFieldElement) {
            LongArray longArray = (LongArray) this.f672x.clone();
            longArray.addShiftedByWords(((F2m) eCFieldElement).f672x, 0);
            return new F2m(this.f670m, this.f671ks, longArray);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement addOne() {
            return new F2m(this.f670m, this.f671ks, this.f672x.addOne());
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return add(eCFieldElement);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            return new F2m(this.f670m, this.f671ks, this.f672x.modMultiply(((F2m) eCFieldElement).f672x, this.f670m, this.f671ks));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            LongArray longArray = this.f672x;
            LongArray longArray2 = ((F2m) eCFieldElement).f672x;
            LongArray longArray3 = ((F2m) eCFieldElement2).f672x;
            LongArray longArray4 = ((F2m) eCFieldElement3).f672x;
            LongArray multiply = longArray.multiply(longArray2, this.f670m, this.f671ks);
            LongArray multiply2 = longArray3.multiply(longArray4, this.f670m, this.f671ks);
            if (multiply == longArray || multiply == longArray2) {
                multiply = (LongArray) multiply.clone();
            }
            multiply.addShiftedByWords(multiply2, 0);
            multiply.reduce(this.f670m, this.f671ks);
            return new F2m(this.f670m, this.f671ks, multiply);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return multiply(eCFieldElement.invert());
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement negate() {
            return this;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement square() {
            return new F2m(this.f670m, this.f671ks, this.f672x.modSquare(this.f670m, this.f671ks));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return squarePlusProduct(eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            LongArray longArray = this.f672x;
            LongArray longArray2 = ((F2m) eCFieldElement).f672x;
            LongArray longArray3 = ((F2m) eCFieldElement2).f672x;
            LongArray square = longArray.square(this.f670m, this.f671ks);
            LongArray multiply = longArray2.multiply(longArray3, this.f670m, this.f671ks);
            if (square == longArray) {
                square = (LongArray) square.clone();
            }
            square.addShiftedByWords(multiply, 0);
            square.reduce(this.f670m, this.f671ks);
            return new F2m(this.f670m, this.f671ks, square);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement squarePow(int i) {
            return i < 1 ? this : new F2m(this.f670m, this.f671ks, this.f672x.modSquareN(i, this.f670m, this.f671ks));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement invert() {
            return new F2m(this.f670m, this.f671ks, this.f672x.modInverse(this.f670m, this.f671ks));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement sqrt() {
            return (this.f672x.isZero() || this.f672x.isOne()) ? this : squarePow(this.f670m - 1);
        }

        public int getRepresentation() {
            return this.representation;
        }

        public int getM() {
            return this.f670m;
        }

        public int getK1() {
            return this.f671ks[0];
        }

        public int getK2() {
            if (this.f671ks.length >= 2) {
                return this.f671ks[1];
            }
            return 0;
        }

        public int getK3() {
            if (this.f671ks.length >= 3) {
                return this.f671ks[2];
            }
            return 0;
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof F2m) {
                F2m f2m = (F2m) obj;
                return this.f670m == f2m.f670m && this.representation == f2m.representation && Arrays.areEqual(this.f671ks, f2m.f671ks) && this.f672x.equals(f2m.f672x);
            }
            return false;
        }

        public int hashCode() {
            return (this.f672x.hashCode() ^ this.f670m) ^ Arrays.hashCode(this.f671ks);
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$Fp */
    /* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ECFieldElement$Fp.class */
    public static class C0278Fp extends AbstractFp {

        /* renamed from: q */
        BigInteger f673q;

        /* renamed from: r */
        BigInteger f674r;

        /* renamed from: x */
        BigInteger f675x;

        /* JADX INFO: Access modifiers changed from: package-private */
        public static BigInteger calculateResidue(BigInteger bigInteger) {
            int bitLength = bigInteger.bitLength();
            if (bitLength < 96 || bigInteger.shiftRight(bitLength - 64).longValue() != -1) {
                return null;
            }
            return ONE.shiftLeft(bitLength).subtract(bigInteger);
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public C0278Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            if (bigInteger3 == null || bigInteger3.signum() < 0 || bigInteger3.compareTo(bigInteger) >= 0) {
                throw new IllegalArgumentException("x value invalid in Fp field element");
            }
            this.f673q = bigInteger;
            this.f674r = bigInteger2;
            this.f675x = bigInteger3;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public BigInteger toBigInteger() {
            return this.f675x;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public String getFieldName() {
            return "Fp";
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public int getFieldSize() {
            return this.f673q.bitLength();
        }

        public BigInteger getQ() {
            return this.f673q;
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement add(ECFieldElement eCFieldElement) {
            return new C0278Fp(this.f673q, this.f674r, modAdd(this.f675x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement addOne() {
            BigInteger add = this.f675x.add(ECConstants.ONE);
            if (add.compareTo(this.f673q) == 0) {
                add = ECConstants.ZERO;
            }
            return new C0278Fp(this.f673q, this.f674r, add);
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return new C0278Fp(this.f673q, this.f674r, modSubtract(this.f675x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            return new C0278Fp(this.f673q, this.f674r, modMult(this.f675x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            BigInteger bigInteger = this.f675x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            BigInteger bigInteger4 = eCFieldElement3.toBigInteger();
            return new C0278Fp(this.f673q, this.f674r, modReduce(bigInteger.multiply(bigInteger2).subtract(bigInteger3.multiply(bigInteger4))));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            BigInteger bigInteger = this.f675x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            BigInteger bigInteger4 = eCFieldElement3.toBigInteger();
            return new C0278Fp(this.f673q, this.f674r, modReduce(bigInteger.multiply(bigInteger2).add(bigInteger3.multiply(bigInteger4))));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return new C0278Fp(this.f673q, this.f674r, modMult(this.f675x, modInverse(eCFieldElement.toBigInteger())));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement negate() {
            return this.f675x.signum() == 0 ? this : new C0278Fp(this.f673q, this.f674r, this.f673q.subtract(this.f675x));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement square() {
            return new C0278Fp(this.f673q, this.f674r, modMult(this.f675x, this.f675x));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            BigInteger bigInteger = this.f675x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            return new C0278Fp(this.f673q, this.f674r, modReduce(bigInteger.multiply(bigInteger).subtract(bigInteger2.multiply(bigInteger3))));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            BigInteger bigInteger = this.f675x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            return new C0278Fp(this.f673q, this.f674r, modReduce(bigInteger.multiply(bigInteger).add(bigInteger2.multiply(bigInteger3))));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement invert() {
            return new C0278Fp(this.f673q, this.f674r, modInverse(this.f675x));
        }

        @Override // org.bouncycastle.math.p010ec.ECFieldElement
        public ECFieldElement sqrt() {
            if (isZero() || isOne()) {
                return this;
            }
            if (!this.f673q.testBit(0)) {
                throw new RuntimeException("not done yet");
            }
            if (this.f673q.testBit(1)) {
                return checkSqrt(new C0278Fp(this.f673q, this.f674r, this.f675x.modPow(this.f673q.shiftRight(2).add(ECConstants.ONE), this.f673q)));
            } else if (this.f673q.testBit(2)) {
                BigInteger modPow = this.f675x.modPow(this.f673q.shiftRight(3), this.f673q);
                BigInteger modMult = modMult(modPow, this.f675x);
                if (modMult(modMult, modPow).equals(ECConstants.ONE)) {
                    return checkSqrt(new C0278Fp(this.f673q, this.f674r, modMult));
                }
                return checkSqrt(new C0278Fp(this.f673q, this.f674r, modMult(modMult, ECConstants.TWO.modPow(this.f673q.shiftRight(2), this.f673q))));
            } else {
                BigInteger shiftRight = this.f673q.shiftRight(1);
                if (!this.f675x.modPow(shiftRight, this.f673q).equals(ECConstants.ONE)) {
                    return null;
                }
                BigInteger bigInteger = this.f675x;
                BigInteger modDouble = modDouble(modDouble(bigInteger));
                BigInteger add = shiftRight.add(ECConstants.ONE);
                BigInteger subtract = this.f673q.subtract(ECConstants.ONE);
                Random random = new Random();
                while (true) {
                    BigInteger bigInteger2 = new BigInteger(this.f673q.bitLength(), random);
                    if (bigInteger2.compareTo(this.f673q) < 0 && modReduce(bigInteger2.multiply(bigInteger2).subtract(modDouble)).modPow(shiftRight, this.f673q).equals(subtract)) {
                        BigInteger[] lucasSequence = lucasSequence(bigInteger2, bigInteger, add);
                        BigInteger bigInteger3 = lucasSequence[0];
                        BigInteger bigInteger4 = lucasSequence[1];
                        if (modMult(bigInteger4, bigInteger4).equals(modDouble)) {
                            return new C0278Fp(this.f673q, this.f674r, modHalfAbs(bigInteger4));
                        }
                        if (!bigInteger3.equals(ECConstants.ONE) && !bigInteger3.equals(subtract)) {
                            return null;
                        }
                    }
                }
            }
        }

        private ECFieldElement checkSqrt(ECFieldElement eCFieldElement) {
            if (eCFieldElement.square().equals(this)) {
                return eCFieldElement;
            }
            return null;
        }

        private BigInteger[] lucasSequence(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            int bitLength = bigInteger3.bitLength();
            int lowestSetBit = bigInteger3.getLowestSetBit();
            BigInteger bigInteger4 = ECConstants.ONE;
            BigInteger bigInteger5 = ECConstants.TWO;
            BigInteger bigInteger6 = bigInteger;
            BigInteger bigInteger7 = ECConstants.ONE;
            BigInteger bigInteger8 = ECConstants.ONE;
            for (int i = bitLength - 1; i >= lowestSetBit + 1; i--) {
                bigInteger7 = modMult(bigInteger7, bigInteger8);
                if (bigInteger3.testBit(i)) {
                    bigInteger8 = modMult(bigInteger7, bigInteger2);
                    bigInteger4 = modMult(bigInteger4, bigInteger6);
                    bigInteger5 = modReduce(bigInteger6.multiply(bigInteger5).subtract(bigInteger.multiply(bigInteger7)));
                    bigInteger6 = modReduce(bigInteger6.multiply(bigInteger6).subtract(bigInteger8.shiftLeft(1)));
                } else {
                    bigInteger8 = bigInteger7;
                    bigInteger4 = modReduce(bigInteger4.multiply(bigInteger5).subtract(bigInteger7));
                    bigInteger6 = modReduce(bigInteger6.multiply(bigInteger5).subtract(bigInteger.multiply(bigInteger7)));
                    bigInteger5 = modReduce(bigInteger5.multiply(bigInteger5).subtract(bigInteger7.shiftLeft(1)));
                }
            }
            BigInteger modMult = modMult(bigInteger7, bigInteger8);
            BigInteger modMult2 = modMult(modMult, bigInteger2);
            BigInteger modReduce = modReduce(bigInteger4.multiply(bigInteger5).subtract(modMult));
            BigInteger modReduce2 = modReduce(bigInteger6.multiply(bigInteger5).subtract(bigInteger.multiply(modMult)));
            BigInteger modMult3 = modMult(modMult, modMult2);
            for (int i2 = 1; i2 <= lowestSetBit; i2++) {
                modReduce = modMult(modReduce, modReduce2);
                modReduce2 = modReduce(modReduce2.multiply(modReduce2).subtract(modMult3.shiftLeft(1)));
                modMult3 = modMult(modMult3, modMult3);
            }
            return new BigInteger[]{modReduce, modReduce2};
        }

        protected BigInteger modAdd(BigInteger bigInteger, BigInteger bigInteger2) {
            BigInteger add = bigInteger.add(bigInteger2);
            if (add.compareTo(this.f673q) >= 0) {
                add = add.subtract(this.f673q);
            }
            return add;
        }

        protected BigInteger modDouble(BigInteger bigInteger) {
            BigInteger shiftLeft = bigInteger.shiftLeft(1);
            if (shiftLeft.compareTo(this.f673q) >= 0) {
                shiftLeft = shiftLeft.subtract(this.f673q);
            }
            return shiftLeft;
        }

        protected BigInteger modHalf(BigInteger bigInteger) {
            if (bigInteger.testBit(0)) {
                bigInteger = this.f673q.add(bigInteger);
            }
            return bigInteger.shiftRight(1);
        }

        protected BigInteger modHalfAbs(BigInteger bigInteger) {
            if (bigInteger.testBit(0)) {
                bigInteger = this.f673q.subtract(bigInteger);
            }
            return bigInteger.shiftRight(1);
        }

        protected BigInteger modInverse(BigInteger bigInteger) {
            return BigIntegers.modOddInverse(this.f673q, bigInteger);
        }

        protected BigInteger modMult(BigInteger bigInteger, BigInteger bigInteger2) {
            return modReduce(bigInteger.multiply(bigInteger2));
        }

        protected BigInteger modReduce(BigInteger bigInteger) {
            if (this.f674r != null) {
                boolean z = bigInteger.signum() < 0;
                if (z) {
                    bigInteger = bigInteger.abs();
                }
                int bitLength = this.f673q.bitLength();
                boolean equals = this.f674r.equals(ECConstants.ONE);
                while (bigInteger.bitLength() > bitLength + 1) {
                    BigInteger shiftRight = bigInteger.shiftRight(bitLength);
                    BigInteger subtract = bigInteger.subtract(shiftRight.shiftLeft(bitLength));
                    if (!equals) {
                        shiftRight = shiftRight.multiply(this.f674r);
                    }
                    bigInteger = shiftRight.add(subtract);
                }
                while (bigInteger.compareTo(this.f673q) >= 0) {
                    bigInteger = bigInteger.subtract(this.f673q);
                }
                if (z && bigInteger.signum() != 0) {
                    bigInteger = this.f673q.subtract(bigInteger);
                }
            } else {
                bigInteger = bigInteger.mod(this.f673q);
            }
            return bigInteger;
        }

        protected BigInteger modSubtract(BigInteger bigInteger, BigInteger bigInteger2) {
            BigInteger subtract = bigInteger.subtract(bigInteger2);
            if (subtract.signum() < 0) {
                subtract = subtract.add(this.f673q);
            }
            return subtract;
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof C0278Fp) {
                C0278Fp c0278Fp = (C0278Fp) obj;
                return this.f673q.equals(c0278Fp.f673q) && this.f675x.equals(c0278Fp.f675x);
            }
            return false;
        }

        public int hashCode() {
            return this.f673q.hashCode() ^ this.f675x.hashCode();
        }
    }

    public abstract BigInteger toBigInteger();

    public abstract String getFieldName();

    public abstract int getFieldSize();

    public abstract ECFieldElement add(ECFieldElement eCFieldElement);

    public abstract ECFieldElement addOne();

    public abstract ECFieldElement subtract(ECFieldElement eCFieldElement);

    public abstract ECFieldElement multiply(ECFieldElement eCFieldElement);

    public abstract ECFieldElement divide(ECFieldElement eCFieldElement);

    public abstract ECFieldElement negate();

    public abstract ECFieldElement square();

    public abstract ECFieldElement invert();

    public abstract ECFieldElement sqrt();

    public int bitLength() {
        return toBigInteger().bitLength();
    }

    public boolean isOne() {
        return bitLength() == 1;
    }

    public boolean isZero() {
        return 0 == toBigInteger().signum();
    }

    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiply(eCFieldElement).subtract(eCFieldElement2.multiply(eCFieldElement3));
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiply(eCFieldElement).add(eCFieldElement2.multiply(eCFieldElement3));
    }

    public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return square().subtract(eCFieldElement.multiply(eCFieldElement2));
    }

    public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
        return square().add(eCFieldElement.multiply(eCFieldElement2));
    }

    public ECFieldElement squarePow(int i) {
        ECFieldElement eCFieldElement = this;
        for (int i2 = 0; i2 < i; i2++) {
            eCFieldElement = eCFieldElement.square();
        }
        return eCFieldElement;
    }

    public boolean testBitZero() {
        return toBigInteger().testBit(0);
    }

    public String toString() {
        return toBigInteger().toString(16);
    }

    public byte[] getEncoded() {
        return BigIntegers.asUnsignedByteArray((getFieldSize() + 7) / 8, toBigInteger());
    }
}