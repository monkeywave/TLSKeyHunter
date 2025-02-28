package org.bouncycastle.pqc.math.linearalgebra;

import java.security.SecureRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/math/linearalgebra/PolynomialGF2mSmallM.class */
public class PolynomialGF2mSmallM {
    private GF2mField field;
    private int degree;
    private int[] coefficients;
    public static final char RANDOM_IRREDUCIBLE_POLYNOMIAL = 'I';

    public PolynomialGF2mSmallM(GF2mField gF2mField) {
        this.field = gF2mField;
        this.degree = -1;
        this.coefficients = new int[1];
    }

    public PolynomialGF2mSmallM(GF2mField gF2mField, int i, char c, SecureRandom secureRandom) {
        this.field = gF2mField;
        switch (c) {
            case 'I':
                this.coefficients = createRandomIrreduciblePolynomial(i, secureRandom);
                computeDegree();
                return;
            default:
                throw new IllegalArgumentException(" Error: type " + c + " is not defined for GF2smallmPolynomial");
        }
    }

    private int[] createRandomIrreduciblePolynomial(int i, SecureRandom secureRandom) {
        int[] iArr = new int[i + 1];
        iArr[i] = 1;
        iArr[0] = this.field.getRandomNonZeroElement(secureRandom);
        for (int i2 = 1; i2 < i; i2++) {
            iArr[i2] = this.field.getRandomElement(secureRandom);
        }
        while (!isIrreducible(iArr)) {
            int nextInt = RandUtils.nextInt(secureRandom, i);
            if (nextInt == 0) {
                iArr[0] = this.field.getRandomNonZeroElement(secureRandom);
            } else {
                iArr[nextInt] = this.field.getRandomElement(secureRandom);
            }
        }
        return iArr;
    }

    public PolynomialGF2mSmallM(GF2mField gF2mField, int i) {
        this.field = gF2mField;
        this.degree = i;
        this.coefficients = new int[i + 1];
        this.coefficients[i] = 1;
    }

    public PolynomialGF2mSmallM(GF2mField gF2mField, int[] iArr) {
        this.field = gF2mField;
        this.coefficients = normalForm(iArr);
        computeDegree();
    }

    public PolynomialGF2mSmallM(GF2mField gF2mField, byte[] bArr) {
        this.field = gF2mField;
        int i = 8;
        int i2 = 1;
        while (gF2mField.getDegree() > i) {
            i2++;
            i += 8;
        }
        if (bArr.length % i2 != 0) {
            throw new IllegalArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
        }
        this.coefficients = new int[bArr.length / i2];
        int i3 = 0;
        for (int i4 = 0; i4 < this.coefficients.length; i4++) {
            for (int i5 = 0; i5 < i; i5 += 8) {
                int[] iArr = this.coefficients;
                int i6 = i4;
                int i7 = i3;
                i3++;
                iArr[i6] = iArr[i6] ^ ((bArr[i7] & 255) << i5);
            }
            if (!this.field.isElementOfThisField(this.coefficients[i4])) {
                throw new IllegalArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
            }
        }
        if (this.coefficients.length != 1 && this.coefficients[this.coefficients.length - 1] == 0) {
            throw new IllegalArgumentException(" Error: byte array is not encoded polynomial over given finite field GF2m");
        }
        computeDegree();
    }

    public PolynomialGF2mSmallM(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        this.field = polynomialGF2mSmallM.field;
        this.degree = polynomialGF2mSmallM.degree;
        this.coefficients = IntUtils.clone(polynomialGF2mSmallM.coefficients);
    }

    public PolynomialGF2mSmallM(GF2mVector gF2mVector) {
        this(gF2mVector.getField(), gF2mVector.getIntArrayForm());
    }

    public int getDegree() {
        int length = this.coefficients.length - 1;
        if (this.coefficients[length] == 0) {
            return -1;
        }
        return length;
    }

    public int getHeadCoefficient() {
        if (this.degree == -1) {
            return 0;
        }
        return this.coefficients[this.degree];
    }

    private static int headCoefficient(int[] iArr) {
        int computeDegree = computeDegree(iArr);
        if (computeDegree == -1) {
            return 0;
        }
        return iArr[computeDegree];
    }

    public int getCoefficient(int i) {
        if (i < 0 || i > this.degree) {
            return 0;
        }
        return this.coefficients[i];
    }

    public byte[] getEncoded() {
        int i = 8;
        int i2 = 1;
        while (this.field.getDegree() > i) {
            i2++;
            i += 8;
        }
        byte[] bArr = new byte[this.coefficients.length * i2];
        int i3 = 0;
        for (int i4 = 0; i4 < this.coefficients.length; i4++) {
            for (int i5 = 0; i5 < i; i5 += 8) {
                int i6 = i3;
                i3++;
                bArr[i6] = (byte) (this.coefficients[i4] >>> i5);
            }
        }
        return bArr;
    }

    public int evaluateAt(int i) {
        int i2 = this.coefficients[this.degree];
        for (int i3 = this.degree - 1; i3 >= 0; i3--) {
            i2 = this.field.mult(i2, i) ^ this.coefficients[i3];
        }
        return i2;
    }

    public PolynomialGF2mSmallM add(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        return new PolynomialGF2mSmallM(this.field, add(this.coefficients, polynomialGF2mSmallM.coefficients));
    }

    public void addToThis(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        this.coefficients = add(this.coefficients, polynomialGF2mSmallM.coefficients);
        computeDegree();
    }

    private int[] add(int[] iArr, int[] iArr2) {
        int[] iArr3;
        int[] iArr4;
        if (iArr.length < iArr2.length) {
            iArr3 = new int[iArr2.length];
            System.arraycopy(iArr2, 0, iArr3, 0, iArr2.length);
            iArr4 = iArr;
        } else {
            iArr3 = new int[iArr.length];
            System.arraycopy(iArr, 0, iArr3, 0, iArr.length);
            iArr4 = iArr2;
        }
        for (int length = iArr4.length - 1; length >= 0; length--) {
            iArr3[length] = this.field.add(iArr3[length], iArr4[length]);
        }
        return iArr3;
    }

    public PolynomialGF2mSmallM addMonomial(int i) {
        int[] iArr = new int[i + 1];
        iArr[i] = 1;
        return new PolynomialGF2mSmallM(this.field, add(this.coefficients, iArr));
    }

    public PolynomialGF2mSmallM multWithElement(int i) {
        if (this.field.isElementOfThisField(i)) {
            return new PolynomialGF2mSmallM(this.field, multWithElement(this.coefficients, i));
        }
        throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");
    }

    public void multThisWithElement(int i) {
        if (!this.field.isElementOfThisField(i)) {
            throw new ArithmeticException("Not an element of the finite field this polynomial is defined over.");
        }
        this.coefficients = multWithElement(this.coefficients, i);
        computeDegree();
    }

    private int[] multWithElement(int[] iArr, int i) {
        int computeDegree = computeDegree(iArr);
        if (computeDegree == -1 || i == 0) {
            return new int[1];
        }
        if (i == 1) {
            return IntUtils.clone(iArr);
        }
        int[] iArr2 = new int[computeDegree + 1];
        for (int i2 = computeDegree; i2 >= 0; i2--) {
            iArr2[i2] = this.field.mult(iArr[i2], i);
        }
        return iArr2;
    }

    public PolynomialGF2mSmallM multWithMonomial(int i) {
        return new PolynomialGF2mSmallM(this.field, multWithMonomial(this.coefficients, i));
    }

    private static int[] multWithMonomial(int[] iArr, int i) {
        int computeDegree = computeDegree(iArr);
        if (computeDegree == -1) {
            return new int[1];
        }
        int[] iArr2 = new int[computeDegree + i + 1];
        System.arraycopy(iArr, 0, iArr2, i, computeDegree + 1);
        return iArr2;
    }

    public PolynomialGF2mSmallM[] div(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        int[][] div = div(this.coefficients, polynomialGF2mSmallM.coefficients);
        return new PolynomialGF2mSmallM[]{new PolynomialGF2mSmallM(this.field, div[0]), new PolynomialGF2mSmallM(this.field, div[1])};
    }

    /* JADX WARN: Multi-variable type inference failed */
    /* JADX WARN: Type inference failed for: r0v7, types: [int[], int[][]] */
    private int[][] div(int[] iArr, int[] iArr2) {
        int computeDegree = computeDegree(iArr2);
        int computeDegree2 = computeDegree(iArr) + 1;
        if (computeDegree == -1) {
            throw new ArithmeticException("Division by zero.");
        }
        ?? r0 = {new int[1], new int[computeDegree2]};
        int inverse = this.field.inverse(headCoefficient(iArr2));
        r0[0][0] = 0;
        System.arraycopy(iArr, 0, r0[1], 0, r0[1].length);
        while (computeDegree <= computeDegree(r0[1])) {
            int[] iArr3 = {this.field.mult(headCoefficient(r0[1]), inverse)};
            int[] multWithElement = multWithElement(iArr2, iArr3[0]);
            int computeDegree3 = computeDegree(r0[1]) - computeDegree;
            int[] multWithMonomial = multWithMonomial(multWithElement, computeDegree3);
            r0[0] = add(multWithMonomial(iArr3, computeDegree3), r0[0]);
            r0[1] = add(multWithMonomial, r0[1]);
        }
        return r0;
    }

    public PolynomialGF2mSmallM gcd(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        return new PolynomialGF2mSmallM(this.field, gcd(this.coefficients, polynomialGF2mSmallM.coefficients));
    }

    private int[] gcd(int[] iArr, int[] iArr2) {
        int[] iArr3 = iArr;
        int[] iArr4 = iArr2;
        if (computeDegree(iArr3) == -1) {
            return iArr4;
        }
        while (computeDegree(iArr4) != -1) {
            int[] mod = mod(iArr3, iArr4);
            iArr3 = new int[iArr4.length];
            System.arraycopy(iArr4, 0, iArr3, 0, iArr3.length);
            iArr4 = new int[mod.length];
            System.arraycopy(mod, 0, iArr4, 0, iArr4.length);
        }
        return multWithElement(iArr3, this.field.inverse(headCoefficient(iArr3)));
    }

    public PolynomialGF2mSmallM multiply(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        return new PolynomialGF2mSmallM(this.field, multiply(this.coefficients, polynomialGF2mSmallM.coefficients));
    }

    private int[] multiply(int[] iArr, int[] iArr2) {
        int[] iArr3;
        int[] iArr4;
        int[] add;
        if (computeDegree(iArr) < computeDegree(iArr2)) {
            iArr3 = iArr2;
            iArr4 = iArr;
        } else {
            iArr3 = iArr;
            iArr4 = iArr2;
        }
        int[] normalForm = normalForm(iArr3);
        int[] normalForm2 = normalForm(iArr4);
        if (normalForm2.length == 1) {
            return multWithElement(normalForm, normalForm2[0]);
        }
        int length = normalForm.length;
        int length2 = normalForm2.length;
        int[] iArr5 = new int[(length + length2) - 1];
        if (length2 != length) {
            int[] iArr6 = new int[length2];
            int[] iArr7 = new int[length - length2];
            System.arraycopy(normalForm, 0, iArr6, 0, iArr6.length);
            System.arraycopy(normalForm, length2, iArr7, 0, iArr7.length);
            add = add(multiply(iArr6, normalForm2), multWithMonomial(multiply(iArr7, normalForm2), length2));
        } else {
            int i = (length + 1) >>> 1;
            int i2 = length - i;
            int[] iArr8 = new int[i];
            int[] iArr9 = new int[i];
            int[] iArr10 = new int[i2];
            int[] iArr11 = new int[i2];
            System.arraycopy(normalForm, 0, iArr8, 0, iArr8.length);
            System.arraycopy(normalForm, i, iArr10, 0, iArr10.length);
            System.arraycopy(normalForm2, 0, iArr9, 0, iArr9.length);
            System.arraycopy(normalForm2, i, iArr11, 0, iArr11.length);
            int[] add2 = add(iArr8, iArr10);
            int[] add3 = add(iArr9, iArr11);
            int[] multiply = multiply(iArr8, iArr9);
            int[] multiply2 = multiply(add2, add3);
            int[] multiply3 = multiply(iArr10, iArr11);
            add = add(multWithMonomial(add(add(add(multiply2, multiply), multiply3), multWithMonomial(multiply3, i)), i), multiply);
        }
        return add;
    }

    private boolean isIrreducible(int[] iArr) {
        if (iArr[0] == 0) {
            return false;
        }
        int computeDegree = computeDegree(iArr) >> 1;
        int[] iArr2 = {0, 1};
        int[] iArr3 = {0, 1};
        int degree = this.field.getDegree();
        for (int i = 0; i < computeDegree; i++) {
            for (int i2 = degree - 1; i2 >= 0; i2--) {
                iArr2 = modMultiply(iArr2, iArr2, iArr);
            }
            iArr2 = normalForm(iArr2);
            if (computeDegree(gcd(add(iArr2, iArr3), iArr)) != 0) {
                return false;
            }
        }
        return true;
    }

    public PolynomialGF2mSmallM mod(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        return new PolynomialGF2mSmallM(this.field, mod(this.coefficients, polynomialGF2mSmallM.coefficients));
    }

    private int[] mod(int[] iArr, int[] iArr2) {
        int computeDegree = computeDegree(iArr2);
        if (computeDegree == -1) {
            throw new ArithmeticException("Division by zero");
        }
        int[] iArr3 = new int[iArr.length];
        int inverse = this.field.inverse(headCoefficient(iArr2));
        System.arraycopy(iArr, 0, iArr3, 0, iArr3.length);
        while (computeDegree <= computeDegree(iArr3)) {
            iArr3 = add(multWithElement(multWithMonomial(iArr2, computeDegree(iArr3) - computeDegree), this.field.mult(headCoefficient(iArr3), inverse)), iArr3);
        }
        return iArr3;
    }

    public PolynomialGF2mSmallM modMultiply(PolynomialGF2mSmallM polynomialGF2mSmallM, PolynomialGF2mSmallM polynomialGF2mSmallM2) {
        return new PolynomialGF2mSmallM(this.field, modMultiply(this.coefficients, polynomialGF2mSmallM.coefficients, polynomialGF2mSmallM2.coefficients));
    }

    public PolynomialGF2mSmallM modSquareMatrix(PolynomialGF2mSmallM[] polynomialGF2mSmallMArr) {
        int length = polynomialGF2mSmallMArr.length;
        int[] iArr = new int[length];
        int[] iArr2 = new int[length];
        for (int i = 0; i < this.coefficients.length; i++) {
            iArr2[i] = this.field.mult(this.coefficients[i], this.coefficients[i]);
        }
        for (int i2 = 0; i2 < length; i2++) {
            for (int i3 = 0; i3 < length; i3++) {
                if (i2 < polynomialGF2mSmallMArr[i3].coefficients.length) {
                    iArr[i2] = this.field.add(iArr[i2], this.field.mult(polynomialGF2mSmallMArr[i3].coefficients[i2], iArr2[i3]));
                }
            }
        }
        return new PolynomialGF2mSmallM(this.field, iArr);
    }

    private int[] modMultiply(int[] iArr, int[] iArr2, int[] iArr3) {
        return mod(multiply(iArr, iArr2), iArr3);
    }

    public PolynomialGF2mSmallM modSquareRoot(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        int[] clone = IntUtils.clone(this.coefficients);
        int[] modMultiply = modMultiply(clone, clone, polynomialGF2mSmallM.coefficients);
        while (true) {
            int[] iArr = modMultiply;
            if (isEqual(iArr, this.coefficients)) {
                return new PolynomialGF2mSmallM(this.field, clone);
            }
            clone = normalForm(iArr);
            modMultiply = modMultiply(clone, clone, polynomialGF2mSmallM.coefficients);
        }
    }

    public PolynomialGF2mSmallM modSquareRootMatrix(PolynomialGF2mSmallM[] polynomialGF2mSmallMArr) {
        int length = polynomialGF2mSmallMArr.length;
        int[] iArr = new int[length];
        for (int i = 0; i < length; i++) {
            for (int i2 = 0; i2 < length; i2++) {
                if (i < polynomialGF2mSmallMArr[i2].coefficients.length && i2 < this.coefficients.length) {
                    iArr[i] = this.field.add(iArr[i], this.field.mult(polynomialGF2mSmallMArr[i2].coefficients[i], this.coefficients[i2]));
                }
            }
        }
        for (int i3 = 0; i3 < length; i3++) {
            iArr[i3] = this.field.sqRoot(iArr[i3]);
        }
        return new PolynomialGF2mSmallM(this.field, iArr);
    }

    public PolynomialGF2mSmallM modDiv(PolynomialGF2mSmallM polynomialGF2mSmallM, PolynomialGF2mSmallM polynomialGF2mSmallM2) {
        return new PolynomialGF2mSmallM(this.field, modDiv(this.coefficients, polynomialGF2mSmallM.coefficients, polynomialGF2mSmallM2.coefficients));
    }

    private int[] modDiv(int[] iArr, int[] iArr2, int[] iArr3) {
        int[] normalForm = normalForm(iArr3);
        int[] mod = mod(iArr2, iArr3);
        int[] iArr4 = {0};
        int[] mod2 = mod(iArr, iArr3);
        while (true) {
            int[] iArr5 = mod2;
            if (computeDegree(mod) == -1) {
                return multWithElement(iArr4, this.field.inverse(headCoefficient(normalForm)));
            }
            int[][] div = div(normalForm, mod);
            normalForm = normalForm(mod);
            mod = normalForm(div[1]);
            int[] add = add(iArr4, modMultiply(div[0], iArr5, iArr3));
            iArr4 = normalForm(iArr5);
            mod2 = normalForm(add);
        }
    }

    public PolynomialGF2mSmallM modInverse(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        return new PolynomialGF2mSmallM(this.field, modDiv(new int[]{1}, this.coefficients, polynomialGF2mSmallM.coefficients));
    }

    public PolynomialGF2mSmallM[] modPolynomialToFracton(PolynomialGF2mSmallM polynomialGF2mSmallM) {
        int i = polynomialGF2mSmallM.degree >> 1;
        int[] normalForm = normalForm(polynomialGF2mSmallM.coefficients);
        int[] mod = mod(this.coefficients, polynomialGF2mSmallM.coefficients);
        int[] iArr = {0};
        int[] iArr2 = {1};
        while (true) {
            int[] iArr3 = iArr2;
            if (computeDegree(mod) <= i) {
                return new PolynomialGF2mSmallM[]{new PolynomialGF2mSmallM(this.field, mod), new PolynomialGF2mSmallM(this.field, iArr3)};
            }
            int[][] div = div(normalForm, mod);
            normalForm = mod;
            mod = div[1];
            iArr = iArr3;
            iArr2 = add(iArr, modMultiply(div[0], iArr3, polynomialGF2mSmallM.coefficients));
        }
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof PolynomialGF2mSmallM)) {
            return false;
        }
        PolynomialGF2mSmallM polynomialGF2mSmallM = (PolynomialGF2mSmallM) obj;
        return this.field.equals(polynomialGF2mSmallM.field) && this.degree == polynomialGF2mSmallM.degree && isEqual(this.coefficients, polynomialGF2mSmallM.coefficients);
    }

    private static boolean isEqual(int[] iArr, int[] iArr2) {
        int computeDegree = computeDegree(iArr);
        if (computeDegree != computeDegree(iArr2)) {
            return false;
        }
        for (int i = 0; i <= computeDegree; i++) {
            if (iArr[i] != iArr2[i]) {
                return false;
            }
        }
        return true;
    }

    public int hashCode() {
        int hashCode = this.field.hashCode();
        for (int i = 0; i < this.coefficients.length; i++) {
            hashCode = (hashCode * 31) + this.coefficients[i];
        }
        return hashCode;
    }

    public String toString() {
        String str = " Polynomial over " + this.field.toString() + ": \n";
        for (int i = 0; i < this.coefficients.length; i++) {
            str = str + this.field.elementToStr(this.coefficients[i]) + "Y^" + i + "+";
        }
        return str + ";";
    }

    private void computeDegree() {
        this.degree = this.coefficients.length - 1;
        while (this.degree >= 0 && this.coefficients[this.degree] == 0) {
            this.degree--;
        }
    }

    private static int computeDegree(int[] iArr) {
        int length = iArr.length - 1;
        while (length >= 0 && iArr[length] == 0) {
            length--;
        }
        return length;
    }

    private static int[] normalForm(int[] iArr) {
        int computeDegree = computeDegree(iArr);
        if (computeDegree == -1) {
            return new int[1];
        }
        if (iArr.length == computeDegree + 1) {
            return IntUtils.clone(iArr);
        }
        int[] iArr2 = new int[computeDegree + 1];
        System.arraycopy(iArr, 0, iArr2, 0, computeDegree + 1);
        return iArr2;
    }
}