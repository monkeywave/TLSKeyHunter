package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ElGamalPrivateKeyParameters.class */
public class ElGamalPrivateKeyParameters extends ElGamalKeyParameters {

    /* renamed from: x */
    private BigInteger f537x;

    public ElGamalPrivateKeyParameters(BigInteger bigInteger, ElGamalParameters elGamalParameters) {
        super(true, elGamalParameters);
        this.f537x = bigInteger;
    }

    public BigInteger getX() {
        return this.f537x;
    }

    @Override // org.bouncycastle.crypto.params.ElGamalKeyParameters
    public boolean equals(Object obj) {
        if ((obj instanceof ElGamalPrivateKeyParameters) && ((ElGamalPrivateKeyParameters) obj).getX().equals(this.f537x)) {
            return super.equals(obj);
        }
        return false;
    }

    @Override // org.bouncycastle.crypto.params.ElGamalKeyParameters
    public int hashCode() {
        return getX().hashCode();
    }
}