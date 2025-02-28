package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DSAPublicKeyParameters.class */
public class DSAPublicKeyParameters extends DSAKeyParameters {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private static final BigInteger TWO = BigInteger.valueOf(2);

    /* renamed from: y */
    private BigInteger f528y;

    public DSAPublicKeyParameters(BigInteger bigInteger, DSAParameters dSAParameters) {
        super(false, dSAParameters);
        this.f528y = validate(bigInteger, dSAParameters);
    }

    private BigInteger validate(BigInteger bigInteger, DSAParameters dSAParameters) {
        if (dSAParameters != null) {
            if (TWO.compareTo(bigInteger) > 0 || dSAParameters.getP().subtract(TWO).compareTo(bigInteger) < 0 || !ONE.equals(bigInteger.modPow(dSAParameters.getQ(), dSAParameters.getP()))) {
                throw new IllegalArgumentException("y value does not appear to be in correct group");
            }
            return bigInteger;
        }
        return bigInteger;
    }

    public BigInteger getY() {
        return this.f528y;
    }
}