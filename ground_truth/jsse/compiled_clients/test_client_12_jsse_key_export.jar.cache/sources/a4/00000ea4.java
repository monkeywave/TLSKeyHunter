package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.pqc.crypto.lms.LMOtsParameters;
import org.bouncycastle.pqc.crypto.lms.LMSigParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/LMSKeyGenParameterSpec.class */
public class LMSKeyGenParameterSpec implements AlgorithmParameterSpec {
    private final LMSigParameters lmSigParams;
    private final LMOtsParameters lmOtsParameters;

    public LMSKeyGenParameterSpec(LMSigParameters lMSigParameters, LMOtsParameters lMOtsParameters) {
        this.lmSigParams = lMSigParameters;
        this.lmOtsParameters = lMOtsParameters;
    }

    public LMSigParameters getSigParams() {
        return this.lmSigParams;
    }

    public LMOtsParameters getOtsParams() {
        return this.lmOtsParameters;
    }
}