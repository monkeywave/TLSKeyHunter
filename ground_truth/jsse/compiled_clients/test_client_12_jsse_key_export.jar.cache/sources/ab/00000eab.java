package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/RainbowPublicKeySpec.class */
public class RainbowPublicKeySpec implements KeySpec {
    private short[][] coeffquadratic;
    private short[][] coeffsingular;
    private short[] coeffscalar;
    private int docLength;

    public RainbowPublicKeySpec(int i, short[][] sArr, short[][] sArr2, short[] sArr3) {
        this.docLength = i;
        this.coeffquadratic = sArr;
        this.coeffsingular = sArr2;
        this.coeffscalar = sArr3;
    }

    public int getDocLength() {
        return this.docLength;
    }

    public short[][] getCoeffQuadratic() {
        return this.coeffquadratic;
    }

    public short[][] getCoeffSingular() {
        return this.coeffsingular;
    }

    public short[] getCoeffScalar() {
        return this.coeffscalar;
    }
}