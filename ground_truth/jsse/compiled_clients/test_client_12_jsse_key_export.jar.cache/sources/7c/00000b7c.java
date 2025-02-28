package org.bouncycastle.jcajce.spec;

import java.math.BigInteger;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHValidationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/spec/DHDomainParameterSpec.class */
public class DHDomainParameterSpec extends DHParameterSpec {

    /* renamed from: q */
    private final BigInteger f622q;

    /* renamed from: j */
    private final BigInteger f623j;

    /* renamed from: m */
    private final int f624m;
    private DHValidationParameters validationParameters;

    public DHDomainParameterSpec(DHParameters dHParameters) {
        this(dHParameters.getP(), dHParameters.getQ(), dHParameters.getG(), dHParameters.getJ(), dHParameters.getM(), dHParameters.getL());
        this.validationParameters = dHParameters.getValidationParameters();
    }

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
        this.f622q = bigInteger2;
        this.f623j = bigInteger4;
        this.f624m = i;
    }

    public BigInteger getQ() {
        return this.f622q;
    }

    public BigInteger getJ() {
        return this.f623j;
    }

    public int getM() {
        return this.f624m;
    }

    public DHParameters getDomainParameters() {
        return new DHParameters(getP(), getG(), this.f622q, this.f624m, getL(), this.f623j, this.validationParameters);
    }
}