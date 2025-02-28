package org.bouncycastle.jce.spec;

import java.security.spec.AlgorithmParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/spec/ElGamalGenParameterSpec.class */
public class ElGamalGenParameterSpec implements AlgorithmParameterSpec {
    private int primeSize;

    public ElGamalGenParameterSpec(int i) {
        this.primeSize = i;
    }

    public int getPrimeSize() {
        return this.primeSize;
    }
}