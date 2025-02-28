package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class SLHDSAKeyParameters extends AsymmetricKeyParameter {
    private final SLHDSAParameters parameters;

    /* JADX INFO: Access modifiers changed from: protected */
    public SLHDSAKeyParameters(boolean z, SLHDSAParameters sLHDSAParameters) {
        super(z);
        this.parameters = sLHDSAParameters;
    }

    public SLHDSAParameters getParameters() {
        return this.parameters;
    }
}