package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: classes2.dex */
public class ElGamalParameters implements CipherParameters {

    /* renamed from: g */
    private BigInteger f852g;

    /* renamed from: l */
    private int f853l;

    /* renamed from: p */
    private BigInteger f854p;

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2) {
        this(bigInteger, bigInteger2, 0);
    }

    public ElGamalParameters(BigInteger bigInteger, BigInteger bigInteger2, int i) {
        this.f852g = bigInteger2;
        this.f854p = bigInteger;
        this.f853l = i;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ElGamalParameters) {
            ElGamalParameters elGamalParameters = (ElGamalParameters) obj;
            return elGamalParameters.getP().equals(this.f854p) && elGamalParameters.getG().equals(this.f852g) && elGamalParameters.getL() == this.f853l;
        }
        return false;
    }

    public BigInteger getG() {
        return this.f852g;
    }

    public int getL() {
        return this.f853l;
    }

    public BigInteger getP() {
        return this.f854p;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG().hashCode()) + this.f853l;
    }
}