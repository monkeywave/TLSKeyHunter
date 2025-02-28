package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class ECPrivateKeySpec extends ECKeySpec {

    /* renamed from: d */
    private BigInteger f972d;

    public ECPrivateKeySpec(BigInteger bigInteger, ECParameterSpec eCParameterSpec) {
        super(eCParameterSpec);
        this.f972d = bigInteger;
    }

    public BigInteger getD() {
        return this.f972d;
    }
}