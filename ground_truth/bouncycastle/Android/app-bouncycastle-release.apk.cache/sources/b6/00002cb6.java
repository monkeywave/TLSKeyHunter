package org.bouncycastle.pqc.legacy.crypto.mceliece;

import org.bouncycastle.pqc.legacy.math.linearalgebra.GF2Matrix;

/* loaded from: classes2.dex */
public class McEliecePublicKeyParameters extends McElieceKeyParameters {

    /* renamed from: g */
    private GF2Matrix f1513g;

    /* renamed from: n */
    private int f1514n;

    /* renamed from: t */
    private int f1515t;

    public McEliecePublicKeyParameters(int i, int i2, GF2Matrix gF2Matrix) {
        super(false, null);
        this.f1514n = i;
        this.f1515t = i2;
        this.f1513g = new GF2Matrix(gF2Matrix);
    }

    public GF2Matrix getG() {
        return this.f1513g;
    }

    public int getK() {
        return this.f1513g.getNumRows();
    }

    public int getN() {
        return this.f1514n;
    }

    public int getT() {
        return this.f1515t;
    }
}