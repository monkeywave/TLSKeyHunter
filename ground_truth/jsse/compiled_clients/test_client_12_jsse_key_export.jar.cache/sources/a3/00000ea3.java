package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/LMSHSSParameterSpec.class */
public class LMSHSSParameterSpec implements AlgorithmParameterSpec {
    private final LMSParameterSpec[] specs;

    public LMSHSSParameterSpec(LMSParameterSpec[] lMSParameterSpecArr) {
        this.specs = (LMSParameterSpec[]) lMSParameterSpecArr.clone();
    }

    public LMSParameterSpec[] getLMSSpecs() {
        return (LMSParameterSpec[]) this.specs.clone();
    }
}