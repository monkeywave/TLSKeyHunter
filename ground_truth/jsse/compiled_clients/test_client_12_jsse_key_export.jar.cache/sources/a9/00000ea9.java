package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/RainbowParameterSpec.class */
public class RainbowParameterSpec implements AlgorithmParameterSpec {
    private static final int[] DEFAULT_VI = {6, 12, 17, 22, 33};

    /* renamed from: vi */
    private int[] f933vi;

    public RainbowParameterSpec() {
        this.f933vi = DEFAULT_VI;
    }

    public RainbowParameterSpec(int[] iArr) {
        this.f933vi = iArr;
        checkParams();
    }

    private void checkParams() {
        if (this.f933vi == null) {
            throw new IllegalArgumentException("no layers defined.");
        }
        if (this.f933vi.length <= 1) {
            throw new IllegalArgumentException("Rainbow needs at least 1 layer, such that v1 < v2.");
        }
        for (int i = 0; i < this.f933vi.length - 1; i++) {
            if (this.f933vi[i] >= this.f933vi[i + 1]) {
                throw new IllegalArgumentException("v[i] has to be smaller than v[i+1]");
            }
        }
    }

    public int getNumOfLayers() {
        return this.f933vi.length - 1;
    }

    public int getDocumentLength() {
        return this.f933vi[this.f933vi.length - 1] - this.f933vi[0];
    }

    public int[] getVi() {
        return Arrays.clone(this.f933vi);
    }
}