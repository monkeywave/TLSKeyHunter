package org.bouncycastle.pqc.legacy.math.linearalgebra;

import java.lang.reflect.Array;
import java.security.SecureRandom;

/* loaded from: classes2.dex */
public final class GoppaCode {

    /* loaded from: classes2.dex */
    public static class MaMaPe {

        /* renamed from: h */
        private GF2Matrix f1535h;

        /* renamed from: p */
        private Permutation f1536p;

        /* renamed from: s */
        private GF2Matrix f1537s;

        public MaMaPe(GF2Matrix gF2Matrix, GF2Matrix gF2Matrix2, Permutation permutation) {
            this.f1537s = gF2Matrix;
            this.f1535h = gF2Matrix2;
            this.f1536p = permutation;
        }

        public GF2Matrix getFirstMatrix() {
            return this.f1537s;
        }

        public Permutation getPermutation() {
            return this.f1536p;
        }

        public GF2Matrix getSecondMatrix() {
            return this.f1535h;
        }
    }

    /* loaded from: classes2.dex */
    public static class MatrixSet {

        /* renamed from: g */
        private GF2Matrix f1538g;
        private int[] setJ;

        public MatrixSet(GF2Matrix gF2Matrix, int[] iArr) {
            this.f1538g = gF2Matrix;
            this.setJ = iArr;
        }

        public GF2Matrix getG() {
            return this.f1538g;
        }

        public int[] getSetJ() {
            return this.setJ;
        }
    }

    private GoppaCode() {
    }

    public static MaMaPe computeSystematicForm(GF2Matrix gF2Matrix, SecureRandom secureRandom) {
        GF2Matrix gF2Matrix2;
        boolean z;
        int numColumns = gF2Matrix.getNumColumns();
        GF2Matrix gF2Matrix3 = null;
        while (true) {
            Permutation permutation = new Permutation(numColumns, secureRandom);
            GF2Matrix gF2Matrix4 = (GF2Matrix) gF2Matrix.rightMultiply(permutation);
            GF2Matrix leftSubMatrix = gF2Matrix4.getLeftSubMatrix();
            try {
                gF2Matrix2 = (GF2Matrix) leftSubMatrix.computeInverse();
                z = true;
            } catch (ArithmeticException unused) {
                gF2Matrix2 = gF2Matrix3;
                z = false;
            }
            if (z) {
                return new MaMaPe(leftSubMatrix, ((GF2Matrix) gF2Matrix2.rightMultiply(gF2Matrix4)).getRightSubMatrix(), permutation);
            }
            gF2Matrix3 = gF2Matrix2;
        }
    }

    public static GF2Matrix createCanonicalCheckMatrix(GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM) {
        int degree = gF2mField.getDegree();
        int i = 1 << degree;
        int degree2 = polynomialGF2mSmallM.getDegree();
        int i2 = 0;
        int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, degree2, i);
        int[][] iArr2 = (int[][]) Array.newInstance(Integer.TYPE, degree2, i);
        for (int i3 = 0; i3 < i; i3++) {
            iArr2[0][i3] = gF2mField.inverse(polynomialGF2mSmallM.evaluateAt(i3));
        }
        for (int i4 = 1; i4 < degree2; i4++) {
            for (int i5 = 0; i5 < i; i5++) {
                iArr2[i4][i5] = gF2mField.mult(iArr2[i4 - 1][i5], i5);
            }
        }
        int i6 = 0;
        while (i6 < degree2) {
            int i7 = i2;
            while (i7 < i) {
                for (int i8 = i2; i8 <= i6; i8++) {
                    int[] iArr3 = iArr[i6];
                    iArr3[i7] = gF2mField.add(iArr3[i7], gF2mField.mult(iArr2[i8][i7], polynomialGF2mSmallM.getCoefficient((degree2 + i8) - i6)));
                }
                i7++;
                i2 = 0;
            }
            i6++;
            i2 = 0;
        }
        int[][] iArr4 = (int[][]) Array.newInstance(Integer.TYPE, degree2 * degree, (i + 31) >>> 5);
        for (int i9 = 0; i9 < i; i9++) {
            int i10 = i9 >>> 5;
            int i11 = 1 << (i9 & 31);
            for (int i12 = 0; i12 < degree2; i12++) {
                int i13 = iArr[i12][i9];
                for (int i14 = 0; i14 < degree; i14++) {
                    if (((i13 >>> i14) & 1) != 0) {
                        int[] iArr5 = iArr4[(((i12 + 1) * degree) - i14) - 1];
                        iArr5[i10] = iArr5[i10] ^ i11;
                    }
                }
            }
        }
        return new GF2Matrix(i, iArr4);
    }

    public static GF2Vector syndromeDecode(GF2Vector gF2Vector, GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM, PolynomialGF2mSmallM[] polynomialGF2mSmallMArr) {
        int degree = 1 << gF2mField.getDegree();
        GF2Vector gF2Vector2 = new GF2Vector(degree);
        if (!gF2Vector.isZero()) {
            PolynomialGF2mSmallM[] modPolynomialToFracton = new PolynomialGF2mSmallM(gF2Vector.toExtensionFieldVector(gF2mField)).modInverse(polynomialGF2mSmallM).addMonomial(1).modSquareRootMatrix(polynomialGF2mSmallMArr).modPolynomialToFracton(polynomialGF2mSmallM);
            PolynomialGF2mSmallM polynomialGF2mSmallM2 = modPolynomialToFracton[0];
            PolynomialGF2mSmallM multiply = polynomialGF2mSmallM2.multiply(polynomialGF2mSmallM2);
            PolynomialGF2mSmallM polynomialGF2mSmallM3 = modPolynomialToFracton[1];
            PolynomialGF2mSmallM add = multiply.add(polynomialGF2mSmallM3.multiply(polynomialGF2mSmallM3).multWithMonomial(1));
            PolynomialGF2mSmallM multWithElement = add.multWithElement(gF2mField.inverse(add.getHeadCoefficient()));
            for (int i = 0; i < degree; i++) {
                if (multWithElement.evaluateAt(i) == 0) {
                    gF2Vector2.setBit(i);
                }
            }
        }
        return gF2Vector2;
    }
}