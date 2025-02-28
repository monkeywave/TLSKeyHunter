package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;
import org.bouncycastle.pqc.crypto.rainbow.util.RainbowUtil;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/Layer.class */
public class Layer {

    /* renamed from: vi */
    private int f894vi;
    private int viNext;

    /* renamed from: oi */
    private int f895oi;
    private short[][][] coeff_alpha;
    private short[][][] coeff_beta;
    private short[][] coeff_gamma;
    private short[] coeff_eta;

    public Layer(byte b, byte b2, short[][][] sArr, short[][][] sArr2, short[][] sArr3, short[] sArr4) {
        this.f894vi = b & 255;
        this.viNext = b2 & 255;
        this.f895oi = this.viNext - this.f894vi;
        this.coeff_alpha = sArr;
        this.coeff_beta = sArr2;
        this.coeff_gamma = sArr3;
        this.coeff_eta = sArr4;
    }

    public Layer(int i, int i2, SecureRandom secureRandom) {
        this.f894vi = i;
        this.viNext = i2;
        this.f895oi = i2 - i;
        this.coeff_alpha = new short[this.f895oi][this.f895oi][this.f894vi];
        this.coeff_beta = new short[this.f895oi][this.f894vi][this.f894vi];
        this.coeff_gamma = new short[this.f895oi][this.viNext];
        this.coeff_eta = new short[this.f895oi];
        int i3 = this.f895oi;
        for (int i4 = 0; i4 < i3; i4++) {
            for (int i5 = 0; i5 < this.f895oi; i5++) {
                for (int i6 = 0; i6 < this.f894vi; i6++) {
                    this.coeff_alpha[i4][i5][i6] = (short) (secureRandom.nextInt() & GF2Field.MASK);
                }
            }
        }
        for (int i7 = 0; i7 < i3; i7++) {
            for (int i8 = 0; i8 < this.f894vi; i8++) {
                for (int i9 = 0; i9 < this.f894vi; i9++) {
                    this.coeff_beta[i7][i8][i9] = (short) (secureRandom.nextInt() & GF2Field.MASK);
                }
            }
        }
        for (int i10 = 0; i10 < i3; i10++) {
            for (int i11 = 0; i11 < this.viNext; i11++) {
                this.coeff_gamma[i10][i11] = (short) (secureRandom.nextInt() & GF2Field.MASK);
            }
        }
        for (int i12 = 0; i12 < i3; i12++) {
            this.coeff_eta[i12] = (short) (secureRandom.nextInt() & GF2Field.MASK);
        }
    }

    public short[][] plugInVinegars(short[] sArr) {
        short[][] sArr2 = new short[this.f895oi][this.f895oi + 1];
        short[] sArr3 = new short[this.f895oi];
        for (int i = 0; i < this.f895oi; i++) {
            for (int i2 = 0; i2 < this.f894vi; i2++) {
                for (int i3 = 0; i3 < this.f894vi; i3++) {
                    sArr3[i] = GF2Field.addElem(sArr3[i], GF2Field.multElem(GF2Field.multElem(this.coeff_beta[i][i2][i3], sArr[i2]), sArr[i3]));
                }
            }
        }
        for (int i4 = 0; i4 < this.f895oi; i4++) {
            for (int i5 = 0; i5 < this.f895oi; i5++) {
                for (int i6 = 0; i6 < this.f894vi; i6++) {
                    sArr2[i4][i5] = GF2Field.addElem(sArr2[i4][i5], GF2Field.multElem(this.coeff_alpha[i4][i5][i6], sArr[i6]));
                }
            }
        }
        for (int i7 = 0; i7 < this.f895oi; i7++) {
            for (int i8 = 0; i8 < this.f894vi; i8++) {
                sArr3[i7] = GF2Field.addElem(sArr3[i7], GF2Field.multElem(this.coeff_gamma[i7][i8], sArr[i8]));
            }
        }
        for (int i9 = 0; i9 < this.f895oi; i9++) {
            for (int i10 = this.f894vi; i10 < this.viNext; i10++) {
                sArr2[i9][i10 - this.f894vi] = GF2Field.addElem(this.coeff_gamma[i9][i10], sArr2[i9][i10 - this.f894vi]);
            }
        }
        for (int i11 = 0; i11 < this.f895oi; i11++) {
            sArr3[i11] = GF2Field.addElem(sArr3[i11], this.coeff_eta[i11]);
        }
        for (int i12 = 0; i12 < this.f895oi; i12++) {
            sArr2[i12][this.f895oi] = sArr3[i12];
        }
        return sArr2;
    }

    public int getVi() {
        return this.f894vi;
    }

    public int getViNext() {
        return this.viNext;
    }

    public int getOi() {
        return this.f895oi;
    }

    public short[][][] getCoeffAlpha() {
        return this.coeff_alpha;
    }

    public short[][][] getCoeffBeta() {
        return this.coeff_beta;
    }

    public short[][] getCoeffGamma() {
        return this.coeff_gamma;
    }

    public short[] getCoeffEta() {
        return this.coeff_eta;
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Layer)) {
            return false;
        }
        Layer layer = (Layer) obj;
        return this.f894vi == layer.getVi() && this.viNext == layer.getViNext() && this.f895oi == layer.getOi() && RainbowUtil.equals(this.coeff_alpha, layer.getCoeffAlpha()) && RainbowUtil.equals(this.coeff_beta, layer.getCoeffBeta()) && RainbowUtil.equals(this.coeff_gamma, layer.getCoeffGamma()) && RainbowUtil.equals(this.coeff_eta, layer.getCoeffEta());
    }

    public int hashCode() {
        return (((((((((((this.f894vi * 37) + this.viNext) * 37) + this.f895oi) * 37) + Arrays.hashCode(this.coeff_alpha)) * 37) + Arrays.hashCode(this.coeff_beta)) * 37) + Arrays.hashCode(this.coeff_gamma)) * 37) + Arrays.hashCode(this.coeff_eta);
    }
}