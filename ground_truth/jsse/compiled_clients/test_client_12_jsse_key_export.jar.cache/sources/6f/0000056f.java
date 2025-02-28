package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/GOST3410Parameters.class */
public class GOST3410Parameters implements CipherParameters {

    /* renamed from: p */
    private BigInteger f539p;

    /* renamed from: q */
    private BigInteger f540q;

    /* renamed from: a */
    private BigInteger f541a;
    private GOST3410ValidationParameters validation;

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f539p = bigInteger;
        this.f540q = bigInteger2;
        this.f541a = bigInteger3;
    }

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, GOST3410ValidationParameters gOST3410ValidationParameters) {
        this.f541a = bigInteger3;
        this.f539p = bigInteger;
        this.f540q = bigInteger2;
        this.validation = gOST3410ValidationParameters;
    }

    public BigInteger getP() {
        return this.f539p;
    }

    public BigInteger getQ() {
        return this.f540q;
    }

    public BigInteger getA() {
        return this.f541a;
    }

    public GOST3410ValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (this.f539p.hashCode() ^ this.f540q.hashCode()) ^ this.f541a.hashCode();
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410Parameters) {
            GOST3410Parameters gOST3410Parameters = (GOST3410Parameters) obj;
            return gOST3410Parameters.getP().equals(this.f539p) && gOST3410Parameters.getQ().equals(this.f540q) && gOST3410Parameters.getA().equals(this.f541a);
        }
        return false;
    }
}