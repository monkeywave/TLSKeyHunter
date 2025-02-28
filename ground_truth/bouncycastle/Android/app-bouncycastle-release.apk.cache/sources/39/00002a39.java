package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.pqc.math.ntru.Polynomial;

/* loaded from: classes2.dex */
class PolynomialPair {

    /* renamed from: a */
    private final Polynomial f1358a;

    /* renamed from: b */
    private final Polynomial f1359b;

    public PolynomialPair(Polynomial polynomial, Polynomial polynomial2) {
        this.f1358a = polynomial;
        this.f1359b = polynomial2;
    }

    /* renamed from: f */
    public Polynomial m22f() {
        return this.f1358a;
    }

    /* renamed from: g */
    public Polynomial m21g() {
        return this.f1359b;
    }

    /* renamed from: m */
    public Polynomial m20m() {
        return this.f1359b;
    }

    /* renamed from: r */
    public Polynomial m19r() {
        return this.f1358a;
    }
}