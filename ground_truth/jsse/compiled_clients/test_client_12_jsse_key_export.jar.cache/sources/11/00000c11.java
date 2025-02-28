package org.bouncycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ECNamedCurveGenParameterSpec.class */
public class ECNamedCurveGenParameterSpec implements AlgorithmParameterSpec {
    private String name;

    public ECNamedCurveGenParameterSpec(String str) {
        this.name = str;
    }

    public String getName() {
        return this.name;
    }
}