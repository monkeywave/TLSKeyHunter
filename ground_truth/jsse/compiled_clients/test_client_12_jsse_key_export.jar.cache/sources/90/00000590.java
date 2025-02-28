package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/SRP6GroupParameters.class */
public class SRP6GroupParameters {

    /* renamed from: N */
    private BigInteger f564N;

    /* renamed from: g */
    private BigInteger f565g;

    public SRP6GroupParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        this.f564N = bigInteger;
        this.f565g = bigInteger2;
    }

    public BigInteger getG() {
        return this.f565g;
    }

    public BigInteger getN() {
        return this.f564N;
    }
}