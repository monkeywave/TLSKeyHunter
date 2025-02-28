package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;

/* loaded from: classes2.dex */
public class GOST3410Parameters implements CipherParameters {

    /* renamed from: a */
    private BigInteger f857a;

    /* renamed from: p */
    private BigInteger f858p;

    /* renamed from: q */
    private BigInteger f859q;
    private GOST3410ValidationParameters validation;

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this.f858p = bigInteger;
        this.f859q = bigInteger2;
        this.f857a = bigInteger3;
    }

    public GOST3410Parameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, GOST3410ValidationParameters gOST3410ValidationParameters) {
        this.f857a = bigInteger3;
        this.f858p = bigInteger;
        this.f859q = bigInteger2;
        this.validation = gOST3410ValidationParameters;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410Parameters) {
            GOST3410Parameters gOST3410Parameters = (GOST3410Parameters) obj;
            return gOST3410Parameters.getP().equals(this.f858p) && gOST3410Parameters.getQ().equals(this.f859q) && gOST3410Parameters.getA().equals(this.f857a);
        }
        return false;
    }

    public BigInteger getA() {
        return this.f857a;
    }

    public BigInteger getP() {
        return this.f858p;
    }

    public BigInteger getQ() {
        return this.f859q;
    }

    public GOST3410ValidationParameters getValidationParameters() {
        return this.validation;
    }

    public int hashCode() {
        return (this.f858p.hashCode() ^ this.f859q.hashCode()) ^ this.f857a.hashCode();
    }
}