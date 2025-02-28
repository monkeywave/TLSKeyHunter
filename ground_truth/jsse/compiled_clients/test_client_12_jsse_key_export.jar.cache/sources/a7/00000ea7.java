package org.bouncycastle.pqc.jcajce.spec;

import java.security.InvalidParameterException;
import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/McElieceKeyGenParameterSpec.class */
public class McElieceKeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;

    /* renamed from: m */
    private int f930m;

    /* renamed from: t */
    private int f931t;

    /* renamed from: n */
    private int f932n;
    private int fieldPoly;

    public McElieceKeyGenParameterSpec() {
        this(11, 50);
    }

    public McElieceKeyGenParameterSpec(int i) {
        if (i < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        this.f930m = 0;
        this.f932n = 1;
        while (this.f932n < i) {
            this.f932n <<= 1;
            this.f930m++;
        }
        this.f931t = this.f932n >>> 1;
        this.f931t /= this.f930m;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(this.f930m);
    }

    public McElieceKeyGenParameterSpec(int i, int i2) throws InvalidParameterException {
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException("m is too large");
        }
        this.f930m = i;
        this.f932n = 1 << i;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f932n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        this.f931t = i2;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i);
    }

    public McElieceKeyGenParameterSpec(int i, int i2, int i3) {
        this.f930m = i;
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException(" m is too large");
        }
        this.f932n = 1 << i;
        this.f931t = i2;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f932n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        if (PolynomialRingGF2.degree(i3) != i || !PolynomialRingGF2.isIrreducible(i3)) {
            throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
        }
        this.fieldPoly = i3;
    }

    public int getM() {
        return this.f930m;
    }

    public int getN() {
        return this.f932n;
    }

    public int getT() {
        return this.f931t;
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }
}