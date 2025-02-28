package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McElieceParameters.class */
public class McElieceParameters implements CipherParameters {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;

    /* renamed from: m */
    private int f876m;

    /* renamed from: t */
    private int f877t;

    /* renamed from: n */
    private int f878n;
    private int fieldPoly;
    private Digest digest;

    public McElieceParameters() {
        this(11, 50);
    }

    public McElieceParameters(Digest digest) {
        this(11, 50, digest);
    }

    public McElieceParameters(int i) {
        this(i, (Digest) null);
    }

    public McElieceParameters(int i, Digest digest) {
        if (i < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        this.f876m = 0;
        this.f878n = 1;
        while (this.f878n < i) {
            this.f878n <<= 1;
            this.f876m++;
        }
        this.f877t = this.f878n >>> 1;
        this.f877t /= this.f876m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.f876m);
        this.digest = digest;
    }

    public McElieceParameters(int i, int i2) {
        this(i, i2, (Digest) null);
    }

    public McElieceParameters(int i, int i2, Digest digest) {
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException("m is too large");
        }
        this.f876m = i;
        this.f878n = 1 << i;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f878n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        this.f877t = i2;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i);
        this.digest = digest;
    }

    public McElieceParameters(int i, int i2, int i3) {
        this(i, i2, i3, null);
    }

    public McElieceParameters(int i, int i2, int i3, Digest digest) {
        this.f876m = i;
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException(" m is too large");
        }
        this.f878n = 1 << i;
        this.f877t = i2;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f878n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        if (PolynomialRingGF2.degree(i3) != i || !PolynomialRingGF2.isIrreducible(i3)) {
            throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
        }
        this.fieldPoly = i3;
        this.digest = digest;
    }

    public int getM() {
        return this.f876m;
    }

    public int getN() {
        return this.f878n;
    }

    public int getT() {
        return this.f877t;
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }
}