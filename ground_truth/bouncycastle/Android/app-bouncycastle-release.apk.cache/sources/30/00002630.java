package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class ElGamalPublicKeySpec extends ElGamalKeySpec {

    /* renamed from: y */
    private BigInteger f977y;

    public ElGamalPublicKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f977y = bigInteger;
    }

    public BigInteger getY() {
        return this.f977y;
    }
}