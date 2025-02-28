package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ElGamalParameters.class */
public class ElGamalParameters implements CipherParameters {

    /* renamed from: g */
    private BigInteger f534g;

    /* renamed from: p */
    private BigInteger f535p;

    /* renamed from: l */
    private int f536l;

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        this(bigInteger, bigInteger2, 0);
    }

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        this.f534g = bigInteger2;
        this.f535p = bigInteger;
        this.f536l = i;
    }

    public BigInteger getP() {
        return this.f535p;
    }

    public BigInteger getG() {
        return this.f534g;
    }

    public int getL() {
        return this.f536l;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ElGamalParameters) {
            ElGamalParameters elGamalParameters = (ElGamalParameters) obj;
            return elGamalParameters.getP().equals(this.f535p) && elGamalParameters.getG().equals(this.f534g) && elGamalParameters.getL() == this.f536l;
        }
        return false;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG().hashCode()) + this.f536l;
    }
}