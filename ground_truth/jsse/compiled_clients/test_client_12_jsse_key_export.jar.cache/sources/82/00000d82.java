package org.bouncycastle.pqc.crypto.mceliece;

import org.bouncycastle.pqc.math.linearalgebra.GF2Matrix;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/mceliece/McEliecePublicKeyParameters.class */
public class McEliecePublicKeyParameters extends McElieceKeyParameters {

    /* renamed from: n */
    private int f888n;

    /* renamed from: t */
    private int f889t;

    /* renamed from: g */
    private GF2Matrix f890g;

    public McEliecePublicKeyParameters(int i, int i2, GF2Matrix gF2Matrix) {
        super(false, null);
        this.f888n = i;
        this.f889t = i2;
        this.f890g = new GF2Matrix(gF2Matrix);
    }

    public int getN() {
        return this.f888n;
    }

    public int getT() {
        return this.f889t;
    }

    public GF2Matrix getG() {
        return this.f890g;
    }

    public int getK() {
        return this.f890g.getNumRows();
    }
}