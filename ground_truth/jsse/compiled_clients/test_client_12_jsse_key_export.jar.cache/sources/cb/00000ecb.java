package org.bouncycastle.pqc.math.linearalgebra;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/math/linearalgebra/PolynomialRingGF2m.class */
public class PolynomialRingGF2m {
    private GF2mField field;

    /* renamed from: p */
    private PolynomialGF2mSmallM f945p;
    protected PolynomialGF2mSmallM[] sqMatrix;
    protected PolynomialGF2mSmallM[] sqRootMatrix;

    public PolynomialRingGF2m(GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM) {
        this.field = gF2mField;
        this.f945p = polynomialGF2mSmallM;
        computeSquaringMatrix();
        computeSquareRootMatrix();
    }

    public PolynomialGF2mSmallM[] getSquaringMatrix() {
        return this.sqMatrix;
    }

    public PolynomialGF2mSmallM[] getSquareRootMatrix() {
        return this.sqRootMatrix;
    }

    private void computeSquaringMatrix() {
        int degree = this.f945p.getDegree();
        this.sqMatrix = new PolynomialGF2mSmallM[degree];
        for (int i = 0; i < (degree >> 1); i++) {
            int[] iArr = new int[(i << 1) + 1];
            iArr[i << 1] = 1;
            this.sqMatrix[i] = new PolynomialGF2mSmallM(this.field, iArr);
        }
        for (int i2 = degree >> 1; i2 < degree; i2++) {
            int[] iArr2 = new int[(i2 << 1) + 1];
            iArr2[i2 << 1] = 1;
            this.sqMatrix[i2] = new PolynomialGF2mSmallM(this.field, iArr2).mod(this.f945p);
        }
    }

    private void computeSquareRootMatrix() {
        int coefficient;
        int degree = this.f945p.getDegree();
        PolynomialGF2mSmallM[] polynomialGF2mSmallMArr = new PolynomialGF2mSmallM[degree];
        for (int i = degree - 1; i >= 0; i--) {
            polynomialGF2mSmallMArr[i] = new PolynomialGF2mSmallM(this.sqMatrix[i]);
        }
        this.sqRootMatrix = new PolynomialGF2mSmallM[degree];
        for (int i2 = degree - 1; i2 >= 0; i2--) {
            this.sqRootMatrix[i2] = new PolynomialGF2mSmallM(this.field, i2);
        }
        for (int i3 = 0; i3 < degree; i3++) {
            if (polynomialGF2mSmallMArr[i3].getCoefficient(i3) == 0) {
                boolean z = false;
                int i4 = i3 + 1;
                while (i4 < degree) {
                    if (polynomialGF2mSmallMArr[i4].getCoefficient(i3) != 0) {
                        z = true;
                        swapColumns(polynomialGF2mSmallMArr, i3, i4);
                        swapColumns(this.sqRootMatrix, i3, i4);
                        i4 = degree;
                    }
                    i4++;
                }
                if (!z) {
                    throw new ArithmeticException("Squaring matrix is not invertible.");
                }
            }
            int inverse = this.field.inverse(polynomialGF2mSmallMArr[i3].getCoefficient(i3));
            polynomialGF2mSmallMArr[i3].multThisWithElement(inverse);
            this.sqRootMatrix[i3].multThisWithElement(inverse);
            for (int i5 = 0; i5 < degree; i5++) {
                if (i5 != i3 && (coefficient = polynomialGF2mSmallMArr[i5].getCoefficient(i3)) != 0) {
                    PolynomialGF2mSmallM multWithElement = polynomialGF2mSmallMArr[i3].multWithElement(coefficient);
                    PolynomialGF2mSmallM multWithElement2 = this.sqRootMatrix[i3].multWithElement(coefficient);
                    polynomialGF2mSmallMArr[i5].addToThis(multWithElement);
                    this.sqRootMatrix[i5].addToThis(multWithElement2);
                }
            }
        }
    }

    private static void swapColumns(PolynomialGF2mSmallM[] polynomialGF2mSmallMArr, int i, int i2) {
        PolynomialGF2mSmallM polynomialGF2mSmallM = polynomialGF2mSmallMArr[i];
        polynomialGF2mSmallMArr[i] = polynomialGF2mSmallMArr[i2];
        polynomialGF2mSmallMArr[i2] = polynomialGF2mSmallM;
    }
}