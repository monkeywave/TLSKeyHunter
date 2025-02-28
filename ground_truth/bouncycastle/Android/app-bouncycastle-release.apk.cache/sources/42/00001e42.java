package org.bouncycastle.crypto.params;

/* loaded from: classes2.dex */
public class DHKeyParameters extends AsymmetricKeyParameter {
    private DHParameters params;

    /* JADX INFO: Access modifiers changed from: protected */
    public DHKeyParameters(boolean z, DHParameters dHParameters) {
        super(z);
        this.params = dHParameters;
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHKeyParameters) {
            DHParameters dHParameters = this.params;
            DHParameters parameters = ((DHKeyParameters) obj).getParameters();
            return dHParameters == null ? parameters == null : dHParameters.equals(parameters);
        }
        return false;
    }

    public DHParameters getParameters() {
        return this.params;
    }

    public int hashCode() {
        int i = !isPrivate();
        DHParameters dHParameters = this.params;
        return dHParameters != null ? i ^ dHParameters.hashCode() : i;
    }
}