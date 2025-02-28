package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DSAKeyParameters.class */
public class DSAKeyParameters extends AsymmetricKeyParameter {
    private DSAParameters params;

    public DSAKeyParameters(boolean z, DSAParameters dSAParameters) {
        super(z);
        this.params = dSAParameters;
    }

    public DSAParameters getParameters() {
        return this.params;
    }
}