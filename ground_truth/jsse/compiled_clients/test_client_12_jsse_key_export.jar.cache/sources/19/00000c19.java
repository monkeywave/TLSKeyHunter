package org.bouncycastle.jce.spec;

import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ElGamalParameterSpec.class */
public class ElGamalParameterSpec implements AlgorithmParameterSpec {

    /* renamed from: p */
    private BigInteger f646p;

    /* renamed from: g */
    private BigInteger f647g;

    public ElGamalParameterSpec(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f646p = bigInteger;
        this.f647g = bigInteger2;
    }

    public BigInteger getP() {
        return this.f646p;
    }

    public BigInteger getG() {
        return this.f647g;
    }
}