package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: classes2.dex */
public class ElGamalParameterSpec implements AlgorithmParameterSpec {

    /* renamed from: g */
    private BigInteger f974g;

    /* renamed from: p */
    private BigInteger f975p;

    public ElGamalParameterSpec(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f975p = bigInteger;
        this.f974g = bigInteger2;
    }

    public BigInteger getG() {
        return this.f974g;
    }

    public BigInteger getP() {
        return this.f975p;
    }
}