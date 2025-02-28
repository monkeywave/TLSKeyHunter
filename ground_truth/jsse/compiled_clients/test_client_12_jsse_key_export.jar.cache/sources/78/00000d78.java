package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McElieceCCA2PublicKeyParameters.class */
public class McElieceCCA2PublicKeyParameters extends McElieceCCA2KeyParameters {

    /* renamed from: n */
    private int f859n;

    /* renamed from: t */
    private int f860t;
    private GF2Matrix matrixG;

    public McElieceCCA2PublicKeyParameters(int i, int i2, GF2Matrix gF2Matrix, String str) {
        super(false, str);
        this.f859n = i;
        this.f860t = i2;
        this.matrixG = new GF2Matrix(gF2Matrix);
    }

    public int getN() {
        return this.f859n;
    }

    public int getT() {
        return this.f860t;
    }

    public GF2Matrix getG() {
        return this.matrixG;
    }

    public int getK() {
        return this.matrixG.getNumRows();
    }
}