package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: classes2.dex */
public class DSAParameters implements CipherParameters {

    /* renamed from: g */
    private BigInteger f842g;

    /* renamed from: p */
    private BigInteger f843p;

    /* renamed from: q */
    private BigInteger f844q;
    private DSAValidationParameters validation;

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f842g = bigInteger3;
        this.f843p = bigInteger;
        this.f844q = bigInteger2;
    }

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, DSAValidationParameters dSAValidationParameters) {
        this.f842g = bigInteger3;
        this.f843p = bigInteger;
        this.f844q = bigInteger2;
        this.validation = dSAValidationParameters;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DSAParameters) {
            DSAParameters dSAParameters = (DSAParameters) obj;
            return dSAParameters.getP().equals(this.f843p) && dSAParameters.getQ().equals(this.f844q) && dSAParameters.getG().equals(this.f842g);
        }
        return false;
    }

    public BigInteger getG() {
        return this.f842g;
    }

    public BigInteger getP() {
        return this.f843p;
    }

    public BigInteger getQ() {
        return this.f844q;
    }

    public DSAValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getQ().hashCode()) ^ getG().hashCode();
    }
}