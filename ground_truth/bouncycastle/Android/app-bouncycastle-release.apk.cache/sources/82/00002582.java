package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;

/* loaded from: classes2.dex */
public class DHDomainParameterSpec extends DHParameterSpec {

    /* renamed from: j */
    private final BigInteger f949j;

    /* renamed from: m */
    private final int f950m;

    /* renamed from: q */
    private final BigInteger f951q;
    private DHValidationParameters validationParameters;

    public DHDomainParameterSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        this(bigInteger, bigInteger2, bigInteger3, null, 0);
    }

    public DHDomainParameterSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, int i) {
        this(bigInteger, bigInteger2, bigInteger3, null, i);
    }

    public DHDomainParameterSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, int i) {
        this(bigInteger, bigInteger2, bigInteger3, bigInteger4, 0, i);
    }

    public DHDomainParameterSpec(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, int i, int i2) {
        super(bigInteger, bigInteger3, i2);
        this.f951q = bigInteger2;
        this.f949j = bigInteger4;
        this.f950m = i;
    }

    public DHDomainParameterSpec(DHParameters dHParameters) {
        this(dHParameters.getP(), dHParameters.getQ(), dHParameters.getG(), dHParameters.getJ(), dHParameters.getM(), dHParameters.getL());
        this.validationParameters = dHParameters.getValidationParameters();
    }

    public DHParameters getDomainParameters() {
        return new DHParameters(getP(), getG(), this.f951q, this.f950m, getL(), this.f949j, this.validationParameters);
    }

    public BigInteger getJ() {
        return this.f949j;
    }

    public int getM() {
        return this.f950m;
    }

    public BigInteger getQ() {
        return this.f951q;
    }
}