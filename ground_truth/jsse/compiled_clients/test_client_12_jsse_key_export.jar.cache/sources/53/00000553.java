package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DSAParameters.class */
public class DSAParameters implements CipherParameters {

    /* renamed from: g */
    private BigInteger f524g;

    /* renamed from: q */
    private BigInteger f525q;

    /* renamed from: p */
    private BigInteger f526p;
    private DSAValidationParameters validation;

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f524g = bigInteger3;
        this.f526p = bigInteger;
        this.f525q = bigInteger2;
    }

    public DSAParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, DSAValidationParameters dSAValidationParameters) {
        this.f524g = bigInteger3;
        this.f526p = bigInteger;
        this.f525q = bigInteger2;
        this.validation = dSAValidationParameters;
    }

    public BigInteger getP() {
        return this.f526p;
    }

    public BigInteger getQ() {
        return this.f525q;
    }

    public BigInteger getG() {
        return this.f524g;
    }

    public DSAValidationParameters getValidationParameters() {
        return this.validation;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DSAParameters) {
            DSAParameters dSAParameters = (DSAParameters) obj;
            return dSAParameters.getP().equals(this.f526p) && dSAParameters.getQ().equals(this.f525q) && dSAParameters.getG().equals(this.f524g);
        }
        return false;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getQ().hashCode()) ^ getG().hashCode();
    }
}