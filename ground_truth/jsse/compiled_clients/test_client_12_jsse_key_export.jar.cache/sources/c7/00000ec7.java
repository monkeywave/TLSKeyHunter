package org.bouncycastle.pqc.math.linearalgebra;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/math/linearalgebra/Matrix.class */
public abstract class Matrix {
    protected int numRows;
    protected int numColumns;
    public static final char MATRIX_TYPE_ZERO = 'Z';
    public static final char MATRIX_TYPE_UNIT = 'I';
    public static final char MATRIX_TYPE_RANDOM_LT = 'L';
    public static final char MATRIX_TYPE_RANDOM_UT = 'U';
    public static final char MATRIX_TYPE_RANDOM_REGULAR = 'R';

    public int getNumRows() {
        return this.numRows;
    }

    public int getNumColumns() {
        return this.numColumns;
    }

    public abstract byte[] getEncoded();

    public abstract Matrix computeInverse();

    public abstract boolean isZero();

    public abstract Matrix rightMultiply(Matrix matrix);

    public abstract Matrix rightMultiply(Permutation permutation);

    public abstract Vector leftMultiply(Vector vector);

    public abstract Vector rightMultiply(Vector vector);

    public abstract String toString();
}