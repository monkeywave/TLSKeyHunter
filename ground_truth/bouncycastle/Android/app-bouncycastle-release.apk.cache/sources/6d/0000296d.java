package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: classes2.dex */
public class DilithiumKeyParameters extends AsymmetricKeyParameter {
    private final DilithiumParameters params;

    public DilithiumKeyParameters(boolean z, DilithiumParameters dilithiumParameters) {
        super(z);
        this.params = dilithiumParameters;
    }

    public DilithiumParameters getParameters() {
        return this.params;
    }
}