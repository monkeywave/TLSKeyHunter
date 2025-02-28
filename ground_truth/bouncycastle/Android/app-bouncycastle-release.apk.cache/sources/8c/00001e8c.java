package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class SRP6GroupParameters {

    /* renamed from: N */
    private BigInteger f882N;

    /* renamed from: g */
    private BigInteger f883g;

    public SRP6GroupParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f882N = bigInteger;
        this.f883g = bigInteger2;
    }

    public BigInteger getG() {
        return this.f883g;
    }

    public BigInteger getN() {
        return this.f882N;
    }
}