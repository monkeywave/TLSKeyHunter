package org.bouncycastle.jce.spec;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ECPrivateKeySpec.class */
public class ECPrivateKeySpec extends ECKeySpec {

    /* renamed from: d */
    private BigInteger f644d;

    public ECPrivateKeySpec(BigInteger bigInteger, ECParameterSpec eCParameterSpec) {
        super(eCParameterSpec);
        this.f644d = bigInteger;
    }

    public BigInteger getD() {
        return this.f644d;
    }
}