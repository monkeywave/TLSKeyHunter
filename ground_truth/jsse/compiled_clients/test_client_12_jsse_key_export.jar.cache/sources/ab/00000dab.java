package org.bouncycastle.pqc.crypto.rainbow;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/RainbowPrivateKeyParameters.class */
public class RainbowPrivateKeyParameters extends RainbowKeyParameters {
    private short[][] A1inv;

    /* renamed from: b1 */
    private short[] f903b1;
    private short[][] A2inv;

    /* renamed from: b2 */
    private short[] f904b2;

    /* renamed from: vi */
    private int[] f905vi;
    private Layer[] layers;

    public RainbowPrivateKeyParameters(short[][] sArr, short[] sArr2, short[][] sArr3, short[] sArr4, int[] iArr, Layer[] layerArr) {
        super(true, iArr[iArr.length - 1] - iArr[0]);
        this.A1inv = sArr;
        this.f903b1 = sArr2;
        this.A2inv = sArr3;
        this.f904b2 = sArr4;
        this.f905vi = iArr;
        this.layers = layerArr;
    }

    public short[] getB1() {
        return this.f903b1;
    }

    public short[][] getInvA1() {
        return this.A1inv;
    }

    public short[] getB2() {
        return this.f904b2;
    }

    public short[][] getInvA2() {
        return this.A2inv;
    }

    public Layer[] getLayers() {
        return this.layers;
    }

    public int[] getVi() {
        return this.f905vi;
    }
}