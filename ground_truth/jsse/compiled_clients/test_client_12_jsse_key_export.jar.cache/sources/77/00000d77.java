package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McElieceCCA2PrivateKeyParameters.class */
public class McElieceCCA2PrivateKeyParameters extends McElieceCCA2KeyParameters {

    /* renamed from: n */
    private int f855n;

    /* renamed from: k */
    private int f856k;
    private GF2mField field;
    private PolynomialGF2mSmallM goppaPoly;

    /* renamed from: p */
    private Permutation f857p;

    /* renamed from: h */
    private GF2Matrix f858h;
    private PolynomialGF2mSmallM[] qInv;

    public McElieceCCA2PrivateKeyParameters(int i, int i2, GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM, Permutation permutation, String str) {
        this(i, i2, gF2mField, polynomialGF2mSmallM, GoppaCode.createCanonicalCheckMatrix(gF2mField, polynomialGF2mSmallM), permutation, str);
    }

    public McElieceCCA2PrivateKeyParameters(int i, int i2, GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM, GF2Matrix gF2Matrix, Permutation permutation, String str) {
        super(true, str);
        this.f855n = i;
        this.f856k = i2;
        this.field = gF2mField;
        this.goppaPoly = polynomialGF2mSmallM;
        this.f858h = gF2Matrix;
        this.f857p = permutation;
        this.qInv = new PolynomialRingGF2m(gF2mField, polynomialGF2mSmallM).getSquareRootMatrix();
    }

    public int getN() {
        return this.f855n;
    }

    public int getK() {
        return this.f856k;
    }

    public int getT() {
        return this.goppaPoly.getDegree();
    }

    public GF2mField getField() {
        return this.field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.goppaPoly;
    }

    public Permutation getP() {
        return this.f857p;
    }

    public GF2Matrix getH() {
        return this.f858h;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.qInv;
    }
}