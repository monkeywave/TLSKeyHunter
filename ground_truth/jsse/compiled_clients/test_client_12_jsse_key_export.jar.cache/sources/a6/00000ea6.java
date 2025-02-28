package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/McElieceCCA2KeyGenParameterSpec.class */
public class McElieceCCA2KeyGenParameterSpec implements AlgorithmParameterSpec {
    public static final String SHA1 = "SHA-1";
    public static final String SHA224 = "SHA-224";
    public static final String SHA256 = "SHA-256";
    public static final String SHA384 = "SHA-384";
    public static final String SHA512 = "SHA-512";
    public static final int DEFAULT_M = 11;
    public static final int DEFAULT_T = 50;

    /* renamed from: m */
    private final int f927m;

    /* renamed from: t */
    private final int f928t;

    /* renamed from: n */
    private final int f929n;
    private int fieldPoly;
    private final String digest;

    public McElieceCCA2KeyGenParameterSpec() {
        this(11, 50, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int i) {
        this(i, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int i, String str) {
        if (i < 1) {
            throw new IllegalArgumentException("key size must be positive");
        }
        int i2 = 0;
        int i3 = 1;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        this.f928t = (i3 >>> 1) / i2;
        this.f927m = i2;
        this.f929n = i3;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i2);
        this.digest = str;
    }

    public McElieceCCA2KeyGenParameterSpec(int i, int i2) {
        this(i, i2, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int i, int i2, String str) {
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException("m is too large");
        }
        this.f927m = i;
        this.f929n = 1 << i;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f929n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        this.f928t = i2;
        this.fieldPoly = PolynomialRingGF2.getIrreduciblePolynomial(i);
        this.digest = str;
    }

    public McElieceCCA2KeyGenParameterSpec(int i, int i2, int i3) {
        this(i, i2, i3, "SHA-256");
    }

    public McElieceCCA2KeyGenParameterSpec(int i, int i2, int i3, String str) {
        this.f927m = i;
        if (i < 1) {
            throw new IllegalArgumentException("m must be positive");
        }
        if (i > 32) {
            throw new IllegalArgumentException(" m is too large");
        }
        this.f929n = 1 << i;
        this.f928t = i2;
        if (i2 < 0) {
            throw new IllegalArgumentException("t must be positive");
        }
        if (i2 > this.f929n) {
            throw new IllegalArgumentException("t must be less than n = 2^m");
        }
        if (PolynomialRingGF2.degree(i3) != i || !PolynomialRingGF2.isIrreducible(i3)) {
            throw new IllegalArgumentException("polynomial is not a field polynomial for GF(2^m)");
        }
        this.fieldPoly = i3;
        this.digest = str;
    }

    public int getM() {
        return this.f927m;
    }

    public int getN() {
        return this.f929n;
    }

    public int getT() {
        return this.f928t;
    }

    public int getFieldPoly() {
        return this.fieldPoly;
    }

    public String getDigest() {
        return this.digest;
    }
}