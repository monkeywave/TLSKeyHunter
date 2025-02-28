package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.KeySpec;
import org.bouncycastle.pqc.crypto.rainbow.Layer;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/spec/RainbowPrivateKeySpec.class */
public class RainbowPrivateKeySpec implements KeySpec {
    private short[][] A1inv;

    /* renamed from: b1 */
    private short[] f934b1;
    private short[][] A2inv;

    /* renamed from: b2 */
    private short[] f935b2;

    /* renamed from: vi */
    private int[] f936vi;
    private Layer[] layers;

    public RainbowPrivateKeySpec(short[][] sArr, short[] sArr2, short[][] sArr3, short[] sArr4, int[] iArr, Layer[] layerArr) {
        this.A1inv = sArr;
        this.f934b1 = sArr2;
        this.A2inv = sArr3;
        this.f935b2 = sArr4;
        this.f936vi = iArr;
        this.layers = layerArr;
    }

    public short[] getB1() {
        return this.f934b1;
    }

    public short[][] getInvA1() {
        return this.A1inv;
    }

    public short[] getB2() {
        return this.f935b2;
    }

    public short[][] getInvA2() {
        return this.A2inv;
    }

    public Layer[] getLayers() {
        return this.layers;
    }

    public int[] getVi() {
        return this.f936vi;
    }
}