package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;
import org.bouncycastle.pqc.math.linearalgebra.GF2mField;
import org.bouncycastle.pqc.math.linearalgebra.GoppaCode;
import org.bouncycastle.pqc.math.linearalgebra.Permutation;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialGF2mSmallM;
import org.bouncycastle.pqc.math.linearalgebra.PolynomialRingGF2m;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McEliecePrivateKeyParameters.class */
public class McEliecePrivateKeyParameters extends McElieceKeyParameters {
    private String oid;

    /* renamed from: n */
    private int f883n;

    /* renamed from: k */
    private int f884k;
    private GF2mField field;
    private PolynomialGF2mSmallM goppaPoly;
    private GF2Matrix sInv;

    /* renamed from: p1 */
    private Permutation f885p1;

    /* renamed from: p2 */
    private Permutation f886p2;

    /* renamed from: h */
    private GF2Matrix f887h;
    private PolynomialGF2mSmallM[] qInv;

    public McEliecePrivateKeyParameters(int i, int i2, GF2mField gF2mField, PolynomialGF2mSmallM polynomialGF2mSmallM, Permutation permutation, Permutation permutation2, GF2Matrix gF2Matrix) {
        super(true, null);
        this.f884k = i2;
        this.f883n = i;
        this.field = gF2mField;
        this.goppaPoly = polynomialGF2mSmallM;
        this.sInv = gF2Matrix;
        this.f885p1 = permutation;
        this.f886p2 = permutation2;
        this.f887h = GoppaCode.createCanonicalCheckMatrix(gF2mField, polynomialGF2mSmallM);
        this.qInv = new PolynomialRingGF2m(gF2mField, polynomialGF2mSmallM).getSquareRootMatrix();
    }

    public McEliecePrivateKeyParameters(int i, int i2, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6, byte[][] bArr7) {
        super(true, null);
        this.f883n = i;
        this.f884k = i2;
        this.field = new GF2mField(bArr);
        this.goppaPoly = new PolynomialGF2mSmallM(this.field, bArr2);
        this.sInv = new GF2Matrix(bArr3);
        this.f885p1 = new Permutation(bArr4);
        this.f886p2 = new Permutation(bArr5);
        this.f887h = new GF2Matrix(bArr6);
        this.qInv = new PolynomialGF2mSmallM[bArr7.length];
        for (int i3 = 0; i3 < bArr7.length; i3++) {
            this.qInv[i3] = new PolynomialGF2mSmallM(this.field, bArr7[i3]);
        }
    }

    public int getN() {
        return this.f883n;
    }

    public int getK() {
        return this.f884k;
    }

    public GF2mField getField() {
        return this.field;
    }

    public PolynomialGF2mSmallM getGoppaPoly() {
        return this.goppaPoly;
    }

    public GF2Matrix getSInv() {
        return this.sInv;
    }

    public Permutation getP1() {
        return this.f885p1;
    }

    public Permutation getP2() {
        return this.f886p2;
    }

    public GF2Matrix getH() {
        return this.f887h;
    }

    public PolynomialGF2mSmallM[] getQInv() {
        return this.qInv;
    }
}