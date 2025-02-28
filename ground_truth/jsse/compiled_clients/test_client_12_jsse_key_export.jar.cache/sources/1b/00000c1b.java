package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ElGamalPublicKeySpec.class */
public class ElGamalPublicKeySpec extends ElGamalKeySpec {

    /* renamed from: y */
    private BigInteger f649y;

    public ElGamalPublicKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f649y = bigInteger;
    }

    public BigInteger getY() {
        return this.f649y;
    }
}