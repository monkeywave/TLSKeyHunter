package org.bouncycastle.jce.spec;

import java.security.spec.KeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ElGamalKeySpec.class */
public class ElGamalKeySpec implements KeySpec {
    private ElGamalParameterSpec spec;

    public ElGamalKeySpec(ElGamalParameterSpec elGamalParameterSpec) {
        this.spec = elGamalParameterSpec;
    }

    public ElGamalParameterSpec getParams() {
        return this.spec;
    }
}