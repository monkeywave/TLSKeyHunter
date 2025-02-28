package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ElGamalPrivateKeySpec.class */
public class ElGamalPrivateKeySpec extends ElGamalKeySpec {

    /* renamed from: x */
    private BigInteger f648x;

    public ElGamalPrivateKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f648x = bigInteger;
    }

    public BigInteger getX() {
        return this.f648x;
    }
}