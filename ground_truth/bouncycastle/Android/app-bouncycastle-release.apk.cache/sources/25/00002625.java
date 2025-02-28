package org.bouncycastle.jce.spec;

import java.security.spec.KeySpec;

/* loaded from: classes2.dex */
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