package org.bouncycastle.math.p016ec;

import java.math.BigInteger;
import java.util.Random;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Integers;

/* renamed from: org.bouncycastle.math.ec.ECFieldElement */
/* loaded from: classes2.dex */
public abstract class ECFieldElement implements ECConstants {

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$AbstractF2m */
    /* loaded from: classes2.dex */
    public static abstract class AbstractF2m extends ECFieldElement {
        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r3v1, types: [org.bouncycastle.math.ec.ECFieldElement] */
        /* JADX WARN: Type inference failed for: r3v3 */
        /* JADX WARN: Type inference failed for: r4v3, types: [org.bouncycastle.math.ec.ECFieldElement] */
        public ECFieldElement halfTrace() {
            int fieldSize = getFieldSize();
            if ((fieldSize & 1) != 0) {
                int i = (fieldSize + 1) >>> 1;
                int numberOfLeadingZeros = 31 - Integers.numberOfLeadingZeros(i);
                ECFieldElement eCFieldElement = this;
                int i2 = 1;
                while (numberOfLeadingZeros > 0) {
                    eCFieldElement = eCFieldElement.squarePow(i2 << 1).add(eCFieldElement);
                    numberOfLeadingZeros--;
                    i2 = i >>> numberOfLeadingZeros;
                    if ((i2 & 1) != 0) {
                        eCFieldElement = eCFieldElement.squarePow(2).add(this);
                    }
                }
                return eCFieldElement;
            }
            throw new IllegalStateException("Half-trace only defined for odd m");
        }

        public boolean hasFastTrace() {
            return false;
        }

        /* JADX WARN: Multi-variable type inference failed */
        /* JADX WARN: Type inference failed for: r3v1, types: [org.bouncycastle.math.ec.ECFieldElement] */
        /* JADX WARN: Type inference failed for: r3v3 */
        /* JADX WARN: Type inference failed for: r4v2, types: [org.bouncycastle.math.ec.ECFieldElement] */
        public int trace() {
            int fieldSize = getFieldSize();
            int numberOfLeadingZeros = 31 - Integers.numberOfLeadingZeros(fieldSize);
            ECFieldElement eCFieldElement = this;
            int i = 1;
            while (numberOfLeadingZeros > 0) {
                eCFieldElement = eCFieldElement.squarePow(i).add(eCFieldElement);
                numberOfLeadingZeros--;
                i = fieldSize >>> numberOfLeadingZeros;
                if ((i & 1) != 0) {
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
    /* loaded from: classes2.dex */
    public static abstract class AbstractFp extends ECFieldElement {
    }

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$F2m */
    /* loaded from: classes2.dex */
    public static class F2m extends AbstractF2m {
        public static final int GNB = 1;
        public static final int PPB = 3;
        public static final int TPB = 2;

        /* renamed from: ks */
        private int[] f1009ks;

        /* renamed from: m */
        private int f1010m;
        private int representation;

        /* renamed from: x */
        LongArray f1011x;

        /* JADX INFO: Access modifiers changed from: package-private */
        public F2m(int i, int[] iArr, LongArray longArray) {
            this.f1010m = i;
            this.representation = iArr.length == 1 ? 2 : 3;
            this.f1009ks = iArr;
            this.f1011x = longArray;
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement add(ECFieldElement eCFieldElement) {
            LongArray longArray = (LongArray) this.f1011x.clone();
            longArray.addShiftedByWords(((F2m) eCFieldElement).f1011x, 0);
            return new F2m(this.f1010m, this.f1009ks, longArray);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement addOne() {
            return new F2m(this.f1010m, this.f1009ks, this.f1011x.addOne());
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public int bitLength() {
            return this.f1011x.degree();
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return multiply(eCFieldElement.invert());
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof F2m) {
                F2m f2m = (F2m) obj;
                return this.f1010m == f2m.f1010m && this.representation == f2m.representation && Arrays.areEqual(this.f1009ks, f2m.f1009ks) && this.f1011x.equals(f2m.f1011x);
            }
            return false;
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public String getFieldName() {
            return "F2m";
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public int getFieldSize() {
            return this.f1010m;
        }

        public int getK1() {
            return this.f1009ks[0];
        }

        public int getK2() {
            int[] iArr = this.f1009ks;
            if (iArr.length >= 2) {
                return iArr[1];
            }
            return 0;
        }

        public int getK3() {
            int[] iArr = this.f1009ks;
            if (iArr.length >= 3) {
                return iArr[2];
            }
            return 0;
        }

        public int getM() {
            return this.f1010m;
        }

        public int getRepresentation() {
            return this.representation;
        }

        public int hashCode() {
            return (this.f1011x.hashCode() ^ this.f1010m) ^ Arrays.hashCode(this.f1009ks);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement invert() {
            int i = this.f1010m;
            int[] iArr = this.f1009ks;
            return new F2m(i, iArr, this.f1011x.modInverse(i, iArr));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public boolean isOne() {
            return this.f1011x.isOne();
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public boolean isZero() {
            return this.f1011x.isZero();
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            int i = this.f1010m;
            int[] iArr = this.f1009ks;
            return new F2m(i, iArr, this.f1011x.modMultiply(((F2m) eCFieldElement).f1011x, i, iArr));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            return multiplyPlusProduct(eCFieldElement, eCFieldElement2, eCFieldElement3);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            LongArray longArray = this.f1011x;
            LongArray longArray2 = ((F2m) eCFieldElement).f1011x;
            LongArray longArray3 = ((F2m) eCFieldElement2).f1011x;
            LongArray longArray4 = ((F2m) eCFieldElement3).f1011x;
            LongArray multiply = longArray.multiply(longArray2, this.f1010m, this.f1009ks);
            LongArray multiply2 = longArray3.multiply(longArray4, this.f1010m, this.f1009ks);
            if (multiply == longArray || multiply == longArray2) {
                multiply = (LongArray) multiply.clone();
            }
            multiply.addShiftedByWords(multiply2, 0);
            multiply.reduce(this.f1010m, this.f1009ks);
            return new F2m(this.f1010m, this.f1009ks, multiply);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement negate() {
            return this;
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement sqrt() {
            return (this.f1011x.isZero() || this.f1011x.isOne()) ? this : squarePow(this.f1010m - 1);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement square() {
            int i = this.f1010m;
            int[] iArr = this.f1009ks;
            return new F2m(i, iArr, this.f1011x.modSquare(i, iArr));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            return squarePlusProduct(eCFieldElement, eCFieldElement2);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            LongArray longArray = this.f1011x;
            LongArray longArray2 = ((F2m) eCFieldElement).f1011x;
            LongArray longArray3 = ((F2m) eCFieldElement2).f1011x;
            LongArray square = longArray.square(this.f1010m, this.f1009ks);
            LongArray multiply = longArray2.multiply(longArray3, this.f1010m, this.f1009ks);
            if (square == longArray) {
                square = (LongArray) square.clone();
            }
            square.addShiftedByWords(multiply, 0);
            square.reduce(this.f1010m, this.f1009ks);
            return new F2m(this.f1010m, this.f1009ks, square);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement squarePow(int i) {
            if (i < 1) {
                return this;
            }
            int i2 = this.f1010m;
            int[] iArr = this.f1009ks;
            return new F2m(i2, iArr, this.f1011x.modSquareN(i, i2, iArr));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return add(eCFieldElement);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public boolean testBitZero() {
            return this.f1011x.testBitZero();
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public BigInteger toBigInteger() {
            return this.f1011x.toBigInteger();
        }
    }

    /* renamed from: org.bouncycastle.math.ec.ECFieldElement$Fp */
    /* loaded from: classes2.dex */
    public static class C1334Fp extends AbstractFp {

        /* renamed from: q */
        BigInteger f1012q;

        /* renamed from: r */
        BigInteger f1013r;

        /* renamed from: x */
        BigInteger f1014x;

        /* JADX INFO: Access modifiers changed from: package-private */
        public C1334Fp(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
            this.f1012q = bigInteger;
            this.f1013r = bigInteger2;
            this.f1014x = bigInteger3;
        }

        /* JADX INFO: Access modifiers changed from: package-private */
        public static BigInteger calculateResidue(BigInteger bigInteger) {
            int bitLength = bigInteger.bitLength();
            if (bitLength < 96 || bigInteger.shiftRight(bitLength - 64).longValue() != -1) {
                return null;
            }
            return ONE.shiftLeft(bitLength).subtract(bigInteger);
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
            BigInteger bigInteger6 = ECConstants.ONE;
            BigInteger bigInteger7 = ECConstants.ONE;
            BigInteger bigInteger8 = bigInteger;
            for (int i = bitLength - 1; i >= lowestSetBit + 1; i--) {
                bigInteger6 = modMult(bigInteger6, bigInteger7);
                if (bigInteger3.testBit(i)) {
                    bigInteger7 = modMult(bigInteger6, bigInteger2);
                    bigInteger4 = modMult(bigInteger4, bigInteger8);
                    bigInteger5 = modReduce(bigInteger8.multiply(bigInteger5).subtract(bigInteger.multiply(bigInteger6)));
                    bigInteger8 = modReduce(bigInteger8.multiply(bigInteger8).subtract(bigInteger7.shiftLeft(1)));
                } else {
                    bigInteger4 = modReduce(bigInteger4.multiply(bigInteger5).subtract(bigInteger6));
                    BigInteger modReduce = modReduce(bigInteger8.multiply(bigInteger5).subtract(bigInteger.multiply(bigInteger6)));
                    bigInteger5 = modReduce(bigInteger5.multiply(bigInteger5).subtract(bigInteger6.shiftLeft(1)));
                    bigInteger8 = modReduce;
                    bigInteger7 = bigInteger6;
                }
            }
            BigInteger modMult = modMult(bigInteger6, bigInteger7);
            BigInteger modMult2 = modMult(modMult, bigInteger2);
            BigInteger modReduce2 = modReduce(bigInteger4.multiply(bigInteger5).subtract(modMult));
            BigInteger modReduce3 = modReduce(bigInteger8.multiply(bigInteger5).subtract(bigInteger.multiply(modMult)));
            BigInteger modMult3 = modMult(modMult, modMult2);
            for (int i2 = 1; i2 <= lowestSetBit; i2++) {
                modReduce2 = modMult(modReduce2, modReduce3);
                modReduce3 = modReduce(modReduce3.multiply(modReduce3).subtract(modMult3.shiftLeft(1)));
                modMult3 = modMult(modMult3, modMult3);
            }
            return new BigInteger[]{modReduce2, modReduce3};
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement add(ECFieldElement eCFieldElement) {
            return new C1334Fp(this.f1012q, this.f1013r, modAdd(this.f1014x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement addOne() {
            BigInteger add = this.f1014x.add(ECConstants.ONE);
            if (add.compareTo(this.f1012q) == 0) {
                add = ECConstants.ZERO;
            }
            return new C1334Fp(this.f1012q, this.f1013r, add);
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement divide(ECFieldElement eCFieldElement) {
            return new C1334Fp(this.f1012q, this.f1013r, modMult(this.f1014x, modInverse(eCFieldElement.toBigInteger())));
        }

        public boolean equals(Object obj) {
            if (obj == this) {
                return true;
            }
            if (obj instanceof C1334Fp) {
                C1334Fp c1334Fp = (C1334Fp) obj;
                return this.f1012q.equals(c1334Fp.f1012q) && this.f1014x.equals(c1334Fp.f1014x);
            }
            return false;
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public String getFieldName() {
            return "Fp";
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public int getFieldSize() {
            return this.f1012q.bitLength();
        }

        public BigInteger getQ() {
            return this.f1012q;
        }

        public int hashCode() {
            return this.f1012q.hashCode() ^ this.f1014x.hashCode();
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement invert() {
            return new C1334Fp(this.f1012q, this.f1013r, modInverse(this.f1014x));
        }

        protected BigInteger modAdd(BigInteger bigInteger, BigInteger bigInteger2) {
            BigInteger add = bigInteger.add(bigInteger2);
            return add.compareTo(this.f1012q) >= 0 ? add.subtract(this.f1012q) : add;
        }

        protected BigInteger modDouble(BigInteger bigInteger) {
            BigInteger shiftLeft = bigInteger.shiftLeft(1);
            return shiftLeft.compareTo(this.f1012q) >= 0 ? shiftLeft.subtract(this.f1012q) : shiftLeft;
        }

        protected BigInteger modHalf(BigInteger bigInteger) {
            if (bigInteger.testBit(0)) {
                bigInteger = this.f1012q.add(bigInteger);
            }
            return bigInteger.shiftRight(1);
        }

        protected BigInteger modHalfAbs(BigInteger bigInteger) {
            if (bigInteger.testBit(0)) {
                bigInteger = this.f1012q.subtract(bigInteger);
            }
            return bigInteger.shiftRight(1);
        }

        protected BigInteger modInverse(BigInteger bigInteger) {
            return BigIntegers.modOddInverse(this.f1012q, bigInteger);
        }

        protected BigInteger modMult(BigInteger bigInteger, BigInteger bigInteger2) {
            return modReduce(bigInteger.multiply(bigInteger2));
        }

        protected BigInteger modReduce(BigInteger bigInteger) {
            if (this.f1013r != null) {
                boolean z = bigInteger.signum() < 0;
                if (z) {
                    bigInteger = bigInteger.abs();
                }
                int bitLength = this.f1012q.bitLength();
                boolean equals = this.f1013r.equals(ECConstants.ONE);
                while (bigInteger.bitLength() > bitLength + 1) {
                    BigInteger shiftRight = bigInteger.shiftRight(bitLength);
                    BigInteger subtract = bigInteger.subtract(shiftRight.shiftLeft(bitLength));
                    if (!equals) {
                        shiftRight = shiftRight.multiply(this.f1013r);
                    }
                    bigInteger = shiftRight.add(subtract);
                }
                while (bigInteger.compareTo(this.f1012q) >= 0) {
                    bigInteger = bigInteger.subtract(this.f1012q);
                }
                return (!z || bigInteger.signum() == 0) ? bigInteger : this.f1012q.subtract(bigInteger);
            }
            return bigInteger.mod(this.f1012q);
        }

        protected BigInteger modSubtract(BigInteger bigInteger, BigInteger bigInteger2) {
            BigInteger subtract = bigInteger.subtract(bigInteger2);
            return subtract.signum() < 0 ? subtract.add(this.f1012q) : subtract;
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiply(ECFieldElement eCFieldElement) {
            return new C1334Fp(this.f1012q, this.f1013r, modMult(this.f1014x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            BigInteger bigInteger = this.f1014x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            BigInteger bigInteger4 = eCFieldElement3.toBigInteger();
            return new C1334Fp(this.f1012q, this.f1013r, modReduce(bigInteger.multiply(bigInteger2).subtract(bigInteger3.multiply(bigInteger4))));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
            BigInteger bigInteger = this.f1014x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            BigInteger bigInteger4 = eCFieldElement3.toBigInteger();
            return new C1334Fp(this.f1012q, this.f1013r, modReduce(bigInteger.multiply(bigInteger2).add(bigInteger3.multiply(bigInteger4))));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement negate() {
            if (this.f1014x.signum() == 0) {
                return this;
            }
            BigInteger bigInteger = this.f1012q;
            return new C1334Fp(bigInteger, this.f1013r, bigInteger.subtract(this.f1014x));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement sqrt() {
            if (isZero() || isOne()) {
                return this;
            }
            if (!this.f1012q.testBit(0)) {
                throw new RuntimeException("not done yet");
            }
            if (this.f1012q.testBit(1)) {
                BigInteger add = this.f1012q.shiftRight(2).add(ECConstants.ONE);
                BigInteger bigInteger = this.f1012q;
                return checkSqrt(new C1334Fp(bigInteger, this.f1013r, this.f1014x.modPow(add, bigInteger)));
            } else if (this.f1012q.testBit(2)) {
                BigInteger modPow = this.f1014x.modPow(this.f1012q.shiftRight(3), this.f1012q);
                BigInteger modMult = modMult(modPow, this.f1014x);
                if (modMult(modMult, modPow).equals(ECConstants.ONE)) {
                    return checkSqrt(new C1334Fp(this.f1012q, this.f1013r, modMult));
                }
                return checkSqrt(new C1334Fp(this.f1012q, this.f1013r, modMult(modMult, ECConstants.TWO.modPow(this.f1012q.shiftRight(2), this.f1012q))));
            } else {
                BigInteger shiftRight = this.f1012q.shiftRight(1);
                if (!this.f1014x.modPow(shiftRight, this.f1012q).equals(ECConstants.ONE)) {
                    return null;
                }
                BigInteger bigInteger2 = this.f1014x;
                BigInteger modDouble = modDouble(modDouble(bigInteger2));
                BigInteger add2 = shiftRight.add(ECConstants.ONE);
                BigInteger subtract = this.f1012q.subtract(ECConstants.ONE);
                Random random = new Random();
                while (true) {
                    BigInteger bigInteger3 = new BigInteger(this.f1012q.bitLength(), random);
                    if (bigInteger3.compareTo(this.f1012q) < 0 && modReduce(bigInteger3.multiply(bigInteger3).subtract(modDouble)).modPow(shiftRight, this.f1012q).equals(subtract)) {
                        BigInteger[] lucasSequence = lucasSequence(bigInteger3, bigInteger2, add2);
                        BigInteger bigInteger4 = lucasSequence[0];
                        BigInteger bigInteger5 = lucasSequence[1];
                        if (modMult(bigInteger5, bigInteger5).equals(modDouble)) {
                            return new C1334Fp(this.f1012q, this.f1013r, modHalfAbs(bigInteger5));
                        }
                        if (!bigInteger4.equals(ECConstants.ONE) && !bigInteger4.equals(subtract)) {
                            return null;
                        }
                    }
                }
            }
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement square() {
            BigInteger bigInteger = this.f1012q;
            BigInteger bigInteger2 = this.f1013r;
            BigInteger bigInteger3 = this.f1014x;
            return new C1334Fp(bigInteger, bigInteger2, modMult(bigInteger3, bigInteger3));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement squareMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            BigInteger bigInteger = this.f1014x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            return new C1334Fp(this.f1012q, this.f1013r, modReduce(bigInteger.multiply(bigInteger).subtract(bigInteger2.multiply(bigInteger3))));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement squarePlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2) {
            BigInteger bigInteger = this.f1014x;
            BigInteger bigInteger2 = eCFieldElement.toBigInteger();
            BigInteger bigInteger3 = eCFieldElement2.toBigInteger();
            return new C1334Fp(this.f1012q, this.f1013r, modReduce(bigInteger.multiply(bigInteger).add(bigInteger2.multiply(bigInteger3))));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public ECFieldElement subtract(ECFieldElement eCFieldElement) {
            return new C1334Fp(this.f1012q, this.f1013r, modSubtract(this.f1014x, eCFieldElement.toBigInteger()));
        }

        @Override // org.bouncycastle.math.p016ec.ECFieldElement
        public BigInteger toBigInteger() {
            return this.f1014x;
        }
    }

    public abstract ECFieldElement add(ECFieldElement eCFieldElement);

    public abstract ECFieldElement addOne();

    public int bitLength() {
        return toBigInteger().bitLength();
    }

    public abstract ECFieldElement divide(ECFieldElement eCFieldElement);

    public void encodeTo(byte[] bArr, int i) {
        BigIntegers.asUnsignedByteArray(toBigInteger(), bArr, i, getEncodedLength());
    }

    public byte[] getEncoded() {
        return BigIntegers.asUnsignedByteArray(getEncodedLength(), toBigInteger());
    }

    public int getEncodedLength() {
        return (getFieldSize() + 7) / 8;
    }

    public abstract String getFieldName();

    public abstract int getFieldSize();

    public abstract ECFieldElement invert();

    public boolean isOne() {
        return bitLength() == 1;
    }

    public boolean isZero() {
        return toBigInteger().signum() == 0;
    }

    public abstract ECFieldElement multiply(ECFieldElement eCFieldElement);

    public ECFieldElement multiplyMinusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiply(eCFieldElement).subtract(eCFieldElement2.multiply(eCFieldElement3));
    }

    public ECFieldElement multiplyPlusProduct(ECFieldElement eCFieldElement, ECFieldElement eCFieldElement2, ECFieldElement eCFieldElement3) {
        return multiply(eCFieldElement).add(eCFieldElement2.multiply(eCFieldElement3));
    }

    public abstract ECFieldElement negate();

    public abstract ECFieldElement sqrt();

    public abstract ECFieldElement square();

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

    public abstract ECFieldElement subtract(ECFieldElement eCFieldElement);

    public boolean testBitZero() {
        return toBigInteger().testBit(0);
    }

    public abstract BigInteger toBigInteger();

    public String toString() {
        return toBigInteger().toString(16);
    }
}