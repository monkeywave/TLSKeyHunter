package org.bouncycastle.jce.spec;

import java.security.spec.KeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ECKeySpec.class */
public class ECKeySpec implements KeySpec {
    private ECParameterSpec spec;

    /* JADX INFO: Access modifiers changed from: protected */
    public ECKeySpec(ECParameterSpec eCParameterSpec) {
        this.spec = eCParameterSpec;
    }

    public ECParameterSpec getParams() {
        return this.spec;
    }
}