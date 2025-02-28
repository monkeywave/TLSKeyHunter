package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/RainbowParameters.class */
public class RainbowParameters implements CipherParameters {
    private final int[] DEFAULT_VI;

    /* renamed from: vi */
    private int[] f902vi;

    public RainbowParameters() {
        this.DEFAULT_VI = new int[]{6, 12, 17, 22, 33};
        this.f902vi = this.DEFAULT_VI;
    }

    public RainbowParameters(int[] iArr) {
        this.DEFAULT_VI = new int[]{6, 12, 17, 22, 33};
        this.f902vi = iArr;
        checkParams();
    }

    private void checkParams() {
        if (this.f902vi == null) {
            throw new IllegalArgumentException("no layers defined.");
        }
        if (this.f902vi.length <= 1) {
            throw new IllegalArgumentException("Rainbow needs at least 1 layer, such that v1 < v2.");
        }
        for (int i = 0; i < this.f902vi.length - 1; i++) {
            if (this.f902vi[i] >= this.f902vi[i + 1]) {
                throw new IllegalArgumentException("v[i] has to be smaller than v[i+1]");
            }
        }
    }

    public int getNumOfLayers() {
        return this.f902vi.length - 1;
    }

    public int getDocLength() {
        return this.f902vi[this.f902vi.length - 1] - this.f902vi[0];
    }

    public int[] getVi() {
        return this.f902vi;
    }
}