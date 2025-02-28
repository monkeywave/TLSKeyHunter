package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DHKeyParameters.class */
public class DHKeyParameters extends AsymmetricKeyParameter {
    private DHParameters params;

    /* JADX INFO: Access modifiers changed from: protected */
    public DHKeyParameters(boolean z, DHParameters dHParameters) {
        super(z);
        this.params = dHParameters;
    }

    public DHParameters getParameters() {
        return this.params;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHKeyParameters) {
            DHKeyParameters dHKeyParameters = (DHKeyParameters) obj;
            return this.params == null ? dHKeyParameters.getParameters() == null : this.params.equals(dHKeyParameters.getParameters());
        }
        return false;
    }

    public int hashCode() {
        int i = isPrivate() ? 0 : 1;
        if (this.params != null) {
            i ^= this.params.hashCode();
        }
        return i;
    }
}