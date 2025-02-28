package org.bouncycastle.pqc.math.linearalgebra;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/math/linearalgebra/Vector.class */
public abstract class Vector {
    protected int length;

    public final int getLength() {
        return this.length;
    }

    public abstract byte[] getEncoded();

    public abstract boolean isZero();

    public abstract Vector add(Vector vector);

    public abstract Vector multiply(Permutation permutation);

    public abstract boolean equals(Object obj);

    public abstract int hashCode();

    public abstract String toString();
}