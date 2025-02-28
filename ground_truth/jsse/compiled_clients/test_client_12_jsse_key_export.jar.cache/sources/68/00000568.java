package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ElGamalKeyParameters.class */
public class ElGamalKeyParameters extends AsymmetricKeyParameter {
    private ElGamalParameters params;

    /* JADX INFO: Access modifiers changed from: protected */
    public ElGamalKeyParameters(boolean z, ElGamalParameters elGamalParameters) {
        super(z);
        this.params = elGamalParameters;
    }

    public ElGamalParameters getParameters() {
        return this.params;
    }

    public int hashCode() {
        if (this.params != null) {
            return this.params.hashCode();
        }
        return 0;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ElGamalKeyParameters) {
            ElGamalKeyParameters elGamalKeyParameters = (ElGamalKeyParameters) obj;
            return this.params == null ? elGamalKeyParameters.getParameters() == null : this.params.equals(elGamalKeyParameters.getParameters());
        }
        return false;
    }
}