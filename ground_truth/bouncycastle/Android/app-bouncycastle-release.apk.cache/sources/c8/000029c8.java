package org.bouncycastle.pqc.crypto.hqc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class HQCKeyParameters extends AsymmetricKeyParameter {
    private HQCParameters params;

    public HQCKeyParameters(boolean z, HQCParameters hQCParameters) {
        super(z);
        this.params = hQCParameters;
    }

    public HQCParameters getParameters() {
        return this.params;
    }
}