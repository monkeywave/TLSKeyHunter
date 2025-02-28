package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import java.util.Vector;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/NaccacheSternPrivateKeyParameters.class */
public class NaccacheSternPrivateKeyParameters extends NaccacheSternKeyParameters {
    private BigInteger phi_n;
    private Vector smallPrimes;

    public NaccacheSternPrivateKeyParameters(BigInteger bigInteger, BigInteger bigInteger2, int i, Vector vector, BigInteger bigInteger3) {
        super(true, bigInteger, bigInteger2, i);
        this.smallPrimes = vector;
        this.phi_n = bigInteger3;
    }

    public BigInteger getPhi_n() {
        return this.phi_n;
    }

    public Vector getSmallPrimes() {
        return this.smallPrimes;
    }
}