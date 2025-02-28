package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class ElGamalPrivateKeySpec extends ElGamalKeySpec {

    /* renamed from: x */
    private BigInteger f976x;

    public ElGamalPrivateKeySpec(BigInteger bigInteger, ElGamalParameterSpec elGamalParameterSpec) {
        super(elGamalParameterSpec);
        this.f976x = bigInteger;
    }

    public BigInteger getX() {
        return this.f976x;
    }
}