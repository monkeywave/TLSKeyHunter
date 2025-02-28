package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/CramerShoupKeyParameters.class */
public class CramerShoupKeyParameters extends AsymmetricKeyParameter {
    private CramerShoupParameters params;

    /* JADX INFO: Access modifiers changed from: protected */
    public CramerShoupKeyParameters(boolean z, CramerShoupParameters cramerShoupParameters) {
        super(z);
        this.params = cramerShoupParameters;
    }

    public CramerShoupParameters getParameters() {
        return this.params;
    }

    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupKeyParameters) {
            CramerShoupKeyParameters cramerShoupKeyParameters = (CramerShoupKeyParameters) obj;
            return this.params == null ? cramerShoupKeyParameters.getParameters() == null : this.params.equals(cramerShoupKeyParameters.getParameters());
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