package org.bouncycastle.tls.crypto;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class SRP6Group {

    /* renamed from: N */
    private BigInteger f1555N;

    /* renamed from: g */
    private BigInteger f1556g;

    public SRP6Group(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f1555N = bigInteger;
        this.f1556g = bigInteger2;
    }

    public BigInteger getG() {
        return this.f1556g;
    }

    public BigInteger getN() {
        return this.f1555N;
    }
}