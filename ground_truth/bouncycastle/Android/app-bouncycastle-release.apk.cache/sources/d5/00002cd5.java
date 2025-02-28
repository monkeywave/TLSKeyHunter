package org.bouncycastle.pqc.legacy.math.linearalgebra;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class GF2Matrix extends Matrix {
    private int length;
    private int[][] matrix;

    public GF2Matrix(int i, char c) {
        this(i, c, new SecureRandom());
    }

    public GF2Matrix(int i, char c, SecureRandom secureRandom) {
        if (i <= 0) {
            throw new ArithmeticException("Size of matrix is non-positive.");
        }
        if (c == 'I') {
            assignUnitMatrix(i);
        } else if (c == 'L') {
            assignRandomLowerTriangularMatrix(i, secureRandom);
        } else if (c == 'R') {
            assignRandomRegularMatrix(i, secureRandom);
        } else if (c == 'U') {
            assignRandomUpperTriangularMatrix(i, secureRandom);
        } else if (c != 'Z') {
            throw new ArithmeticException("Unknown matrix type.");
        } else {
            assignZeroMatrix(i, i);
        }
    }

    private GF2Matrix(int i, int i2) {
        if (i2 <= 0 || i <= 0) {
            throw new ArithmeticException("size of matrix is non-positive");
        }
        assignZeroMatrix(i, i2);
    }

    public GF2Matrix(int i, int[][] iArr) {
        if (iArr[0].length != ((i + 31) >> 5)) {
            throw new ArithmeticException("Int array does not match given number of columns.");
        }
        this.numColumns = i;
        this.numRows = iArr.length;
        this.length = iArr[0].length;
        int i2 = i & 31;
        int i3 = i2 == 0 ? -1 : (1 << i2) - 1;
        for (int i4 = 0; i4 < this.numRows; i4++) {
            int[] iArr2 = iArr[i4];
            int i5 = this.length - 1;
            iArr2[i5] = iArr2[i5] & i3;
        }
        this.matrix = iArr;
    }

    public GF2Matrix(GF2Matrix gF2Matrix) {
        this.numColumns = gF2Matrix.getNumColumns();
        this.numRows = gF2Matrix.getNumRows();
        this.length = gF2Matrix.length;
        this.matrix = new int[gF2Matrix.matrix.length];
        int i = 0;
        while (true) {
            int[][] iArr = this.matrix;
            if (i >= iArr.length) {
                return;
            }
            iArr[i] = IntUtils.clone(gF2Matrix.matrix[i]);
            i++;
        }
    }

    public GF2Matrix(byte[] bArr) {
        if (bArr.length < 9) {
            throw new ArithmeticException("given array is not an encoded matrix over GF(2)");
        }
        this.numRows = LittleEndianConversions.OS2IP(bArr, 0);
        this.numColumns = LittleEndianConversions.OS2IP(bArr, 4);
        int i = ((this.numColumns + 7) >>> 3) * this.numRows;
        if (this.numRows > 0) {
            int i2 = 8;
            if (i == bArr.length - 8) {
                this.length = (this.numColumns + 31) >>> 5;
                this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
                int i3 = this.numColumns >> 5;
                int i4 = this.numColumns & 31;
                for (int i5 = 0; i5 < this.numRows; i5++) {
                    int i6 = 0;
                    while (i6 < i3) {
                        this.matrix[i5][i6] = LittleEndianConversions.OS2IP(bArr, i2);
                        i6++;
                        i2 += 4;
                    }
                    int i7 = 0;
                    while (i7 < i4) {
                        int[] iArr = this.matrix[i5];
                        iArr[i3] = ((bArr[i2] & UByte.MAX_VALUE) << i7) ^ iArr[i3];
                        i7 += 8;
                        i2++;
                    }
                }
                return;
            }
        }
        throw new ArithmeticException("given array is not an encoded matrix over GF(2)");
    }

    private static void addToRow(int[] iArr, int[] iArr2, int i) {
        for (int length = iArr2.length - 1; length >= i; length--) {
            iArr2[length] = iArr[length] ^ iArr2[length];
        }
    }

    private void assignRandomLowerTriangularMatrix(int i, SecureRandom secureRandom) {
        this.numRows = i;
        this.numColumns = i;
        this.length = (i + 31) >>> 5;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
        for (int i2 = 0; i2 < this.numRows; i2++) {
            int i3 = i2 >>> 5;
            int i4 = i2 & 31;
            int i5 = 31 - i4;
            int i6 = 1 << i4;
            for (int i7 = 0; i7 < i3; i7++) {
                this.matrix[i2][i7] = secureRandom.nextInt();
            }
            this.matrix[i2][i3] = i6 | (secureRandom.nextInt() >>> i5);
            while (true) {
                i3++;
                if (i3 < this.length) {
                    this.matrix[i2][i3] = 0;
                }
            }
        }
    }

    private void assignRandomRegularMatrix(int i, SecureRandom secureRandom) {
        this.numRows = i;
        this.numColumns = i;
        this.length = (i + 31) >>> 5;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
        GF2Matrix gF2Matrix = (GF2Matrix) new GF2Matrix(i, Matrix.MATRIX_TYPE_RANDOM_LT, secureRandom).rightMultiply(new GF2Matrix(i, Matrix.MATRIX_TYPE_RANDOM_UT, secureRandom));
        int[] vector = new Permutation(i, secureRandom).getVector();
        for (int i2 = 0; i2 < i; i2++) {
            System.arraycopy(gF2Matrix.matrix[i2], 0, this.matrix[vector[i2]], 0, this.length);
        }
    }

    private void assignRandomUpperTriangularMatrix(int i, SecureRandom secureRandom) {
        int i2;
        this.numRows = i;
        this.numColumns = i;
        this.length = (i + 31) >>> 5;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
        int i3 = i & 31;
        int i4 = i3 == 0 ? -1 : (1 << i3) - 1;
        for (int i5 = 0; i5 < this.numRows; i5++) {
            int i6 = i5 >>> 5;
            int i7 = i5 & 31;
            for (int i8 = 0; i8 < i6; i8++) {
                this.matrix[i5][i8] = 0;
            }
            this.matrix[i5][i6] = (secureRandom.nextInt() | 1) << i7;
            while (true) {
                i6++;
                i2 = this.length;
                if (i6 < i2) {
                    this.matrix[i5][i6] = secureRandom.nextInt();
                }
            }
            int[] iArr = this.matrix[i5];
            int i9 = i2 - 1;
            iArr[i9] = iArr[i9] & i4;
        }
    }

    private void assignUnitMatrix(int i) {
        this.numRows = i;
        this.numColumns = i;
        this.length = (i + 31) >>> 5;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
        for (int i2 = 0; i2 < this.numRows; i2++) {
            for (int i3 = 0; i3 < this.length; i3++) {
                this.matrix[i2][i3] = 0;
            }
        }
        for (int i4 = 0; i4 < this.numRows; i4++) {
            this.matrix[i4][i4 >>> 5] = 1 << (i4 & 31);
        }
    }

    private void assignZeroMatrix(int i, int i2) {
        this.numRows = i;
        this.numColumns = i2;
        this.length = (i2 + 31) >>> 5;
        this.matrix = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
        for (int i3 = 0; i3 < this.numRows; i3++) {
            for (int i4 = 0; i4 < this.length; i4++) {
                this.matrix[i3][i4] = 0;
            }
        }
    }

    public static GF2Matrix[] createRandomRegularMatrixAndItsInverse(int i, SecureRandom secureRandom) {
        int i2 = (i + 31) >> 5;
        GF2Matrix gF2Matrix = new GF2Matrix(i, Matrix.MATRIX_TYPE_RANDOM_LT, secureRandom);
        GF2Matrix gF2Matrix2 = new GF2Matrix(i, Matrix.MATRIX_TYPE_RANDOM_UT, secureRandom);
        GF2Matrix gF2Matrix3 = (GF2Matrix) gF2Matrix.rightMultiply(gF2Matrix2);
        Permutation permutation = new Permutation(i, secureRandom);
        int[] vector = permutation.getVector();
        int i3 = 0;
        int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, i, i2);
        for (int i4 = 0; i4 < i; i4++) {
            System.arraycopy(gF2Matrix3.matrix[vector[i4]], 0, iArr[i4], 0, i2);
        }
        GF2Matrix gF2Matrix4 = new GF2Matrix(i, iArr);
        GF2Matrix gF2Matrix5 = new GF2Matrix(i, 'I');
        int i5 = 0;
        while (i5 < i) {
            int i6 = i5 >>> 5;
            int i7 = 1 << (i5 & 31);
            int i8 = i5 + 1;
            int i9 = i8;
            while (i9 < i) {
                if ((gF2Matrix.matrix[i9][i6] & i7) != 0) {
                    for (int i10 = i3; i10 <= i6; i10++) {
                        int[][] iArr2 = gF2Matrix5.matrix;
                        int[] iArr3 = iArr2[i9];
                        iArr3[i10] = iArr3[i10] ^ iArr2[i5][i10];
                    }
                }
                i9++;
                i3 = 0;
            }
            i5 = i8;
        }
        GF2Matrix gF2Matrix6 = new GF2Matrix(i, 'I');
        for (int i11 = i - 1; i11 >= 0; i11--) {
            int i12 = i11 >>> 5;
            int i13 = 1 << (i11 & 31);
            for (int i14 = i11 - 1; i14 >= 0; i14--) {
                if ((gF2Matrix2.matrix[i14][i12] & i13) != 0) {
                    for (int i15 = i12; i15 < i2; i15++) {
                        int[][] iArr4 = gF2Matrix6.matrix;
                        int[] iArr5 = iArr4[i14];
                        iArr5[i15] = iArr4[i11][i15] ^ iArr5[i15];
                    }
                }
            }
        }
        return new GF2Matrix[]{gF2Matrix4, (GF2Matrix) gF2Matrix6.rightMultiply(gF2Matrix5.rightMultiply(permutation))};
    }

    private static void swapRows(int[][] iArr, int i, int i2) {
        int[] iArr2 = iArr[i];
        iArr[i] = iArr[i2];
        iArr[i2] = iArr2;
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public Matrix computeInverse() {
        if (this.numRows == this.numColumns) {
            int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
            for (int i = this.numRows - 1; i >= 0; i--) {
                iArr[i] = IntUtils.clone(this.matrix[i]);
            }
            int[][] iArr2 = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, this.length);
            for (int i2 = this.numRows - 1; i2 >= 0; i2--) {
                iArr2[i2][i2 >> 5] = 1 << (i2 & 31);
            }
            for (int i3 = 0; i3 < this.numRows; i3++) {
                int i4 = i3 >> 5;
                int i5 = 1 << (i3 & 31);
                if ((iArr[i3][i4] & i5) == 0) {
                    int i6 = i3 + 1;
                    boolean z = false;
                    while (i6 < this.numRows) {
                        if ((iArr[i6][i4] & i5) != 0) {
                            swapRows(iArr, i3, i6);
                            swapRows(iArr2, i3, i6);
                            i6 = this.numRows;
                            z = true;
                        }
                        i6++;
                    }
                    if (!z) {
                        throw new ArithmeticException("Matrix is not invertible.");
                    }
                }
                for (int i7 = this.numRows - 1; i7 >= 0; i7--) {
                    if (i7 != i3) {
                        int[] iArr3 = iArr[i7];
                        if ((iArr3[i4] & i5) != 0) {
                            addToRow(iArr[i3], iArr3, i4);
                            addToRow(iArr2[i3], iArr2[i7], 0);
                        }
                    }
                }
            }
            return new GF2Matrix(this.numColumns, iArr2);
        }
        throw new ArithmeticException("Matrix is not invertible.");
    }

    public Matrix computeTranspose() {
        int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, this.numColumns, (this.numRows + 31) >>> 5);
        for (int i = 0; i < this.numRows; i++) {
            for (int i2 = 0; i2 < this.numColumns; i2++) {
                int i3 = i >>> 5;
                int i4 = i & 31;
                if (((this.matrix[i][i2 >>> 5] >>> (i2 & 31)) & 1) == 1) {
                    int[] iArr2 = iArr[i2];
                    iArr2[i3] = (1 << i4) | iArr2[i3];
                }
            }
        }
        return new GF2Matrix(this.numRows, iArr);
    }

    public boolean equals(Object obj) {
        if (obj instanceof GF2Matrix) {
            GF2Matrix gF2Matrix = (GF2Matrix) obj;
            if (this.numRows == gF2Matrix.numRows && this.numColumns == gF2Matrix.numColumns && this.length == gF2Matrix.length) {
                for (int i = 0; i < this.numRows; i++) {
                    if (!IntUtils.equals(this.matrix[i], gF2Matrix.matrix[i])) {
                        return false;
                    }
                }
                return true;
            }
            return false;
        }
        return false;
    }

    public GF2Matrix extendLeftCompactForm() {
        GF2Matrix gF2Matrix = new GF2Matrix(this.numRows, this.numColumns + this.numRows);
        int i = (this.numRows - 1) + this.numColumns;
        int i2 = this.numRows - 1;
        while (i2 >= 0) {
            System.arraycopy(this.matrix[i2], 0, gF2Matrix.matrix[i2], 0, this.length);
            int[] iArr = gF2Matrix.matrix[i2];
            int i3 = i >> 5;
            iArr[i3] = iArr[i3] | (1 << (i & 31));
            i2--;
            i--;
        }
        return gF2Matrix;
    }

    public GF2Matrix extendRightCompactForm() {
        int i;
        GF2Matrix gF2Matrix = new GF2Matrix(this.numRows, this.numRows + this.numColumns);
        int i2 = this.numRows >> 5;
        int i3 = this.numRows & 31;
        for (int i4 = this.numRows - 1; i4 >= 0; i4--) {
            int[] iArr = gF2Matrix.matrix[i4];
            int i5 = i4 >> 5;
            iArr[i5] = iArr[i5] | (1 << (i4 & 31));
            int i6 = 0;
            if (i3 != 0) {
                int i7 = i2;
                while (true) {
                    i = this.length;
                    if (i6 >= i - 1) {
                        break;
                    }
                    int i8 = this.matrix[i4][i6];
                    int[] iArr2 = gF2Matrix.matrix[i4];
                    int i9 = i7 + 1;
                    iArr2[i7] = iArr2[i7] | (i8 << i3);
                    iArr2[i9] = iArr2[i9] | (i8 >>> (32 - i3));
                    i6++;
                    i7 = i9;
                }
                int i10 = this.matrix[i4][i - 1];
                int[] iArr3 = gF2Matrix.matrix[i4];
                int i11 = i7 + 1;
                iArr3[i7] = iArr3[i7] | (i10 << i3);
                if (i11 < gF2Matrix.length) {
                    iArr3[i11] = iArr3[i11] | (i10 >>> (32 - i3));
                }
            } else {
                System.arraycopy(this.matrix[i4], 0, iArr, i2, this.length);
            }
        }
        return gF2Matrix;
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public byte[] getEncoded() {
        int i = 8;
        byte[] bArr = new byte[(((this.numColumns + 7) >>> 3) * this.numRows) + 8];
        LittleEndianConversions.I2OSP(this.numRows, bArr, 0);
        LittleEndianConversions.I2OSP(this.numColumns, bArr, 4);
        int i2 = this.numColumns >>> 5;
        int i3 = this.numColumns & 31;
        for (int i4 = 0; i4 < this.numRows; i4++) {
            int i5 = 0;
            while (i5 < i2) {
                LittleEndianConversions.I2OSP(this.matrix[i4][i5], bArr, i);
                i5++;
                i += 4;
            }
            int i6 = 0;
            while (i6 < i3) {
                bArr[i] = (byte) ((this.matrix[i4][i2] >>> i6) & 255);
                i6 += 8;
                i++;
            }
        }
        return bArr;
    }

    public double getHammingWeight() {
        int i = this.numColumns & 31;
        int i2 = this.length;
        if (i != 0) {
            i2--;
        }
        double d = 0.0d;
        double d2 = 0.0d;
        for (int i3 = 0; i3 < this.numRows; i3++) {
            for (int i4 = 0; i4 < i2; i4++) {
                int i5 = this.matrix[i3][i4];
                for (int i6 = 0; i6 < 32; i6++) {
                    d += (i5 >>> i6) & 1;
                    d2 += 1.0d;
                }
            }
            int i7 = this.matrix[i3][this.length - 1];
            for (int i8 = 0; i8 < i; i8++) {
                d += (i7 >>> i8) & 1;
                d2 += 1.0d;
            }
        }
        return d / d2;
    }

    public int[][] getIntArray() {
        return this.matrix;
    }

    public GF2Matrix getLeftSubMatrix() {
        if (this.numColumns > this.numRows) {
            int i = (this.numRows + 31) >> 5;
            int[][] iArr = (int[][]) Array.newInstance(Integer.TYPE, this.numRows, i);
            int i2 = (1 << (this.numRows & 31)) - 1;
            if (i2 == 0) {
                i2 = -1;
            }
            for (int i3 = this.numRows - 1; i3 >= 0; i3--) {
                System.arraycopy(this.matrix[i3], 0, iArr[i3], 0, i);
                int[] iArr2 = iArr[i3];
                int i4 = i - 1;
                iArr2[i4] = iArr2[i4] & i2;
            }
            return new GF2Matrix(this.numRows, iArr);
        }
        throw new ArithmeticException("empty submatrix");
    }

    public int getLength() {
        return this.length;
    }

    public GF2Matrix getRightSubMatrix() {
        int i;
        if (this.numColumns > this.numRows) {
            int i2 = this.numRows >> 5;
            int i3 = this.numRows & 31;
            GF2Matrix gF2Matrix = new GF2Matrix(this.numRows, this.numColumns - this.numRows);
            for (int i4 = this.numRows - 1; i4 >= 0; i4--) {
                int i5 = 0;
                if (i3 != 0) {
                    int i6 = i2;
                    while (true) {
                        i = gF2Matrix.length;
                        if (i5 >= i - 1) {
                            break;
                        }
                        int[] iArr = gF2Matrix.matrix[i4];
                        int[] iArr2 = this.matrix[i4];
                        int i7 = i6 + 1;
                        iArr[i5] = (iArr2[i6] >>> i3) | (iArr2[i7] << (32 - i3));
                        i5++;
                        i6 = i7;
                    }
                    int[] iArr3 = gF2Matrix.matrix[i4];
                    int[] iArr4 = this.matrix[i4];
                    int i8 = i6 + 1;
                    iArr3[i - 1] = iArr4[i6] >>> i3;
                    if (i8 < this.length) {
                        int i9 = i - 1;
                        iArr3[i9] = iArr3[i9] | (iArr4[i8] << (32 - i3));
                    }
                } else {
                    System.arraycopy(this.matrix[i4], i2, gF2Matrix.matrix[i4], 0, gF2Matrix.length);
                }
            }
            return gF2Matrix;
        }
        throw new ArithmeticException("empty submatrix");
    }

    public int[] getRow(int i) {
        return this.matrix[i];
    }

    public int hashCode() {
        int i = (((this.numRows * 31) + this.numColumns) * 31) + this.length;
        for (int i2 = 0; i2 < this.numRows; i2++) {
            i = (i * 31) + Arrays.hashCode(this.matrix[i2]);
        }
        return i;
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public boolean isZero() {
        for (int i = 0; i < this.numRows; i++) {
            for (int i2 = 0; i2 < this.length; i2++) {
                if (this.matrix[i][i2] != 0) {
                    return false;
                }
            }
        }
        return true;
    }

    public Matrix leftMultiply(Permutation permutation) {
        int[] vector = permutation.getVector();
        if (vector.length == this.numRows) {
            int[][] iArr = new int[this.numRows];
            for (int i = this.numRows - 1; i >= 0; i--) {
                iArr[i] = IntUtils.clone(this.matrix[vector[i]]);
            }
            return new GF2Matrix(this.numRows, iArr);
        }
        throw new ArithmeticException("length mismatch");
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public Vector leftMultiply(Vector vector) {
        if (vector instanceof GF2Vector) {
            if (vector.length == this.numRows) {
                int[] vecArray = ((GF2Vector) vector).getVecArray();
                int[] iArr = new int[this.length];
                int i = this.numRows >> 5;
                int i2 = 1 << (this.numRows & 31);
                int i3 = 0;
                for (int i4 = 0; i4 < i; i4++) {
                    int i5 = 1;
                    do {
                        if ((vecArray[i4] & i5) != 0) {
                            for (int i6 = 0; i6 < this.length; i6++) {
                                iArr[i6] = iArr[i6] ^ this.matrix[i3][i6];
                            }
                        }
                        i3++;
                        i5 <<= 1;
                    } while (i5 != 0);
                }
                for (int i7 = 1; i7 != i2; i7 <<= 1) {
                    if ((vecArray[i] & i7) != 0) {
                        for (int i8 = 0; i8 < this.length; i8++) {
                            iArr[i8] = iArr[i8] ^ this.matrix[i3][i8];
                        }
                    }
                    i3++;
                }
                return new GF2Vector(iArr, this.numColumns);
            }
            throw new ArithmeticException("length mismatch");
        }
        throw new ArithmeticException("vector is not defined over GF(2)");
    }

    public Vector leftMultiplyLeftCompactForm(Vector vector) {
        if (vector instanceof GF2Vector) {
            if (vector.length == this.numRows) {
                int[] vecArray = ((GF2Vector) vector).getVecArray();
                int[] iArr = new int[((this.numRows + this.numColumns) + 31) >>> 5];
                int i = this.numRows >>> 5;
                int i2 = 0;
                for (int i3 = 0; i3 < i; i3++) {
                    int i4 = 1;
                    do {
                        if ((vecArray[i3] & i4) != 0) {
                            for (int i5 = 0; i5 < this.length; i5++) {
                                iArr[i5] = iArr[i5] ^ this.matrix[i2][i5];
                            }
                            int i6 = (this.numColumns + i2) >>> 5;
                            iArr[i6] = (1 << ((this.numColumns + i2) & 31)) | iArr[i6];
                        }
                        i2++;
                        i4 <<= 1;
                    } while (i4 != 0);
                }
                int i7 = 1 << (this.numRows & 31);
                for (int i8 = 1; i8 != i7; i8 <<= 1) {
                    if ((vecArray[i] & i8) != 0) {
                        for (int i9 = 0; i9 < this.length; i9++) {
                            iArr[i9] = iArr[i9] ^ this.matrix[i2][i9];
                        }
                        int i10 = (this.numColumns + i2) >>> 5;
                        iArr[i10] = (1 << ((this.numColumns + i2) & 31)) | iArr[i10];
                    }
                    i2++;
                }
                return new GF2Vector(iArr, this.numRows + this.numColumns);
            }
            throw new ArithmeticException("length mismatch");
        }
        throw new ArithmeticException("vector is not defined over GF(2)");
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public Matrix rightMultiply(Matrix matrix) {
        if (matrix instanceof GF2Matrix) {
            if (matrix.numRows == this.numColumns) {
                GF2Matrix gF2Matrix = (GF2Matrix) matrix;
                GF2Matrix gF2Matrix2 = new GF2Matrix(this.numRows, matrix.numColumns);
                int i = this.numColumns & 31;
                int i2 = this.length;
                if (i != 0) {
                    i2--;
                }
                for (int i3 = 0; i3 < this.numRows; i3++) {
                    int i4 = 0;
                    for (int i5 = 0; i5 < i2; i5++) {
                        int i6 = this.matrix[i3][i5];
                        for (int i7 = 0; i7 < 32; i7++) {
                            if (((1 << i7) & i6) != 0) {
                                for (int i8 = 0; i8 < gF2Matrix.length; i8++) {
                                    int[] iArr = gF2Matrix2.matrix[i3];
                                    iArr[i8] = iArr[i8] ^ gF2Matrix.matrix[i4][i8];
                                }
                            }
                            i4++;
                        }
                    }
                    int i9 = this.matrix[i3][this.length - 1];
                    for (int i10 = 0; i10 < i; i10++) {
                        if (((1 << i10) & i9) != 0) {
                            for (int i11 = 0; i11 < gF2Matrix.length; i11++) {
                                int[] iArr2 = gF2Matrix2.matrix[i3];
                                iArr2[i11] = iArr2[i11] ^ gF2Matrix.matrix[i4][i11];
                            }
                        }
                        i4++;
                    }
                }
                return gF2Matrix2;
            }
            throw new ArithmeticException("length mismatch");
        }
        throw new ArithmeticException("matrix is not defined over GF(2)");
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public Matrix rightMultiply(Permutation permutation) {
        int[] vector = permutation.getVector();
        if (vector.length == this.numColumns) {
            GF2Matrix gF2Matrix = new GF2Matrix(this.numRows, this.numColumns);
            for (int i = this.numColumns - 1; i >= 0; i--) {
                int i2 = i >>> 5;
                int i3 = i & 31;
                int i4 = vector[i];
                int i5 = i4 >>> 5;
                int i6 = i4 & 31;
                for (int i7 = this.numRows - 1; i7 >= 0; i7--) {
                    int[] iArr = gF2Matrix.matrix[i7];
                    iArr[i2] = iArr[i2] | (((this.matrix[i7][i5] >>> i6) & 1) << i3);
                }
            }
            return gF2Matrix;
        }
        throw new ArithmeticException("length mismatch");
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public Vector rightMultiply(Vector vector) {
        if (vector instanceof GF2Vector) {
            if (vector.length == this.numColumns) {
                int[] vecArray = ((GF2Vector) vector).getVecArray();
                int[] iArr = new int[(this.numRows + 31) >>> 5];
                for (int i = 0; i < this.numRows; i++) {
                    int i2 = 0;
                    for (int i3 = 0; i3 < this.length; i3++) {
                        i2 ^= this.matrix[i][i3] & vecArray[i3];
                    }
                    int i4 = 0;
                    for (int i5 = 0; i5 < 32; i5++) {
                        i4 ^= (i2 >>> i5) & 1;
                    }
                    if (i4 == 1) {
                        int i6 = i >>> 5;
                        iArr[i6] = iArr[i6] | (1 << (i & 31));
                    }
                }
                return new GF2Vector(iArr, this.numRows);
            }
            throw new ArithmeticException("length mismatch");
        }
        throw new ArithmeticException("vector is not defined over GF(2)");
    }

    public Vector rightMultiplyRightCompactForm(Vector vector) {
        int i;
        if (vector instanceof GF2Vector) {
            if (vector.length == this.numColumns + this.numRows) {
                int[] vecArray = ((GF2Vector) vector).getVecArray();
                int[] iArr = new int[(this.numRows + 31) >>> 5];
                int i2 = this.numRows >> 5;
                int i3 = this.numRows & 31;
                for (int i4 = 0; i4 < this.numRows; i4++) {
                    int i5 = i4 >> 5;
                    int i6 = i4 & 31;
                    int i7 = (vecArray[i5] >>> i6) & 1;
                    int i8 = i2;
                    int i9 = 0;
                    if (i3 != 0) {
                        while (true) {
                            i = this.length;
                            if (i9 >= i - 1) {
                                break;
                            }
                            int i10 = i8 + 1;
                            i7 ^= ((vecArray[i8] >>> i3) | (vecArray[i10] << (32 - i3))) & this.matrix[i4][i9];
                            i9++;
                            i8 = i10;
                        }
                        int i11 = i8 + 1;
                        int i12 = vecArray[i8] >>> i3;
                        if (i11 < vecArray.length) {
                            i12 |= vecArray[i11] << (32 - i3);
                        }
                        i7 ^= this.matrix[i4][i - 1] & i12;
                    } else {
                        while (i9 < this.length) {
                            i7 ^= vecArray[i8] & this.matrix[i4][i9];
                            i9++;
                            i8++;
                        }
                    }
                    int i13 = 0;
                    for (int i14 = 0; i14 < 32; i14++) {
                        i13 ^= i7 & 1;
                        i7 >>>= 1;
                    }
                    if (i13 == 1) {
                        iArr[i5] = iArr[i5] | (1 << i6);
                    }
                }
                return new GF2Vector(iArr, this.numRows);
            }
            throw new ArithmeticException("length mismatch");
        }
        throw new ArithmeticException("vector is not defined over GF(2)");
    }

    @Override // org.bouncycastle.pqc.legacy.math.linearalgebra.Matrix
    public String toString() {
        int i = this.numColumns & 31;
        int i2 = this.length;
        if (i != 0) {
            i2--;
        }
        StringBuffer stringBuffer = new StringBuffer();
        for (int i3 = 0; i3 < this.numRows; i3++) {
            stringBuffer.append(i3 + ": ");
            for (int i4 = 0; i4 < i2; i4++) {
                int i5 = this.matrix[i3][i4];
                for (int i6 = 0; i6 < 32; i6++) {
                    if (((i5 >>> i6) & 1) == 0) {
                        stringBuffer.append('0');
                    } else {
                        stringBuffer.append('1');
                    }
                }
                stringBuffer.append(' ');
            }
            int i7 = this.matrix[i3][this.length - 1];
            for (int i8 = 0; i8 < i; i8++) {
                if (((i7 >>> i8) & 1) == 0) {
                    stringBuffer.append('0');
                } else {
                    stringBuffer.append('1');
                }
            }
            stringBuffer.append('\n');
        }
        return stringBuffer.toString();
    }
}