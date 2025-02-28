package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/GOST3410PrivateKeyParameters.class */
public class GOST3410PrivateKeyParameters extends GOST3410KeyParameters {

    /* renamed from: x */
    private BigInteger f542x;

    public GOST3410PrivateKeyParameters(BigInteger bigInteger, GOST3410Parameters gOST3410Parameters) {
        super(true, gOST3410Parameters);
        this.f542x = bigInteger;
    }

    public BigInteger getX() {
        return this.f542x;
    }
}