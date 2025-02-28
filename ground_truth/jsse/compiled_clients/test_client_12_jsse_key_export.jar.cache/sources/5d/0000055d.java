package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ECKeyParameters.class */
public class ECKeyParameters extends AsymmetricKeyParameter {
    private final ECDomainParameters parameters;

    /* JADX INFO: Access modifiers changed from: protected */
    public ECKeyParameters(boolean z, ECDomainParameters eCDomainParameters) {
        super(z);
        if (null == eCDomainParameters) {
            throw new NullPointerException("'parameters' cannot be null");
        }
        this.parameters = eCDomainParameters;
    }

    public ECDomainParameters getParameters() {
        return this.parameters;
    }
}