package org.bouncycastle.pqc.legacy.crypto.rainbow;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.pqc.legacy.crypto.rainbow.util.GF2Field;
import org.bouncycastle.pqc.legacy.crypto.rainbow.util.RainbowUtil;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class Layer {
    private short[][][] coeff_alpha;
    private short[][][] coeff_beta;
    private short[] coeff_eta;
    private short[][] coeff_gamma;

    /* renamed from: oi */
    private int f1516oi;

    /* renamed from: vi */
    private int f1517vi;
    private int viNext;

    public Layer(byte b, byte b2, short[][][] sArr, short[][][] sArr2, short[][] sArr3, short[] sArr4) {
        int i = b & UByte.MAX_VALUE;
        this.f1517vi = i;
        int i2 = b2 & UByte.MAX_VALUE;
        this.viNext = i2;
        this.f1516oi = i2 - i;
        this.coeff_alpha = sArr;
        this.coeff_beta = sArr2;
        this.coeff_gamma = sArr3;
        this.coeff_eta = sArr4;
    }

    public Layer(int i, int i2, SecureRandom secureRandom) {
        this.f1517vi = i;
        this.viNext = i2;
        int i3 = i2 - i;
        this.f1516oi = i3;
        this.coeff_alpha = (short[][][]) Array.newInstance(Short.TYPE, i3, i3, i);
        int i4 = this.f1516oi;
        int i5 = this.f1517vi;
        this.coeff_beta = (short[][][]) Array.newInstance(Short.TYPE, i4, i5, i5);
        this.coeff_gamma = (short[][]) Array.newInstance(Short.TYPE, this.f1516oi, this.viNext);
        int i6 = this.f1516oi;
        this.coeff_eta = new short[i6];
        for (int i7 = 0; i7 < i6; i7++) {
            for (int i8 = 0; i8 < this.f1516oi; i8++) {
                for (int i9 = 0; i9 < this.f1517vi; i9++) {
                    this.coeff_alpha[i7][i8][i9] = (short) (secureRandom.nextInt() & 255);
                }
            }
        }
        for (int i10 = 0; i10 < i6; i10++) {
            for (int i11 = 0; i11 < this.f1517vi; i11++) {
                for (int i12 = 0; i12 < this.f1517vi; i12++) {
                    this.coeff_beta[i10][i11][i12] = (short) (secureRandom.nextInt() & 255);
                }
            }
        }
        for (int i13 = 0; i13 < i6; i13++) {
            for (int i14 = 0; i14 < this.viNext; i14++) {
                this.coeff_gamma[i13][i14] = (short) (secureRandom.nextInt() & 255);
            }
        }
        for (int i15 = 0; i15 < i6; i15++) {
            this.coeff_eta[i15] = (short) (secureRandom.nextInt() & 255);
        }
    }

    public boolean equals(Object obj) {
        if (obj == null || !(obj instanceof Layer)) {
            return false;
        }
        Layer layer = (Layer) obj;
        return this.f1517vi == layer.getVi() && this.viNext == layer.getViNext() && this.f1516oi == layer.getOi() && RainbowUtil.equals(this.coeff_alpha, layer.getCoeffAlpha()) && RainbowUtil.equals(this.coeff_beta, layer.getCoeffBeta()) && RainbowUtil.equals(this.coeff_gamma, layer.getCoeffGamma()) && RainbowUtil.equals(this.coeff_eta, layer.getCoeffEta());
    }

    public short[][][] getCoeffAlpha() {
        return this.coeff_alpha;
    }

    public short[][][] getCoeffBeta() {
        return this.coeff_beta;
    }

    public short[] getCoeffEta() {
        return this.coeff_eta;
    }

    public short[][] getCoeffGamma() {
        return this.coeff_gamma;
    }

    public int getOi() {
        return this.f1516oi;
    }

    public int getVi() {
        return this.f1517vi;
    }

    public int getViNext() {
        return this.viNext;
    }

    public int hashCode() {
        return (((((((((((this.f1517vi * 37) + this.viNext) * 37) + this.f1516oi) * 37) + Arrays.hashCode(this.coeff_alpha)) * 37) + Arrays.hashCode(this.coeff_beta)) * 37) + Arrays.hashCode(this.coeff_gamma)) * 37) + Arrays.hashCode(this.coeff_eta);
    }

    public short[][] plugInVinegars(short[] sArr) {
        int i = this.f1516oi;
        int i2 = 0;
        short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, i, i + 1);
        short[] sArr3 = new short[this.f1516oi];
        for (int i3 = 0; i3 < this.f1516oi; i3++) {
            for (int i4 = 0; i4 < this.f1517vi; i4++) {
                for (int i5 = 0; i5 < this.f1517vi; i5++) {
                    sArr3[i3] = GF2Field.addElem(sArr3[i3], GF2Field.multElem(GF2Field.multElem(this.coeff_beta[i3][i4][i5], sArr[i4]), sArr[i5]));
                }
            }
        }
        for (int i6 = 0; i6 < this.f1516oi; i6++) {
            for (int i7 = 0; i7 < this.f1516oi; i7++) {
                for (int i8 = 0; i8 < this.f1517vi; i8++) {
                    short multElem = GF2Field.multElem(this.coeff_alpha[i6][i7][i8], sArr[i8]);
                    short[] sArr4 = sArr2[i6];
                    sArr4[i7] = GF2Field.addElem(sArr4[i7], multElem);
                }
            }
        }
        for (int i9 = 0; i9 < this.f1516oi; i9++) {
            for (int i10 = 0; i10 < this.f1517vi; i10++) {
                sArr3[i9] = GF2Field.addElem(sArr3[i9], GF2Field.multElem(this.coeff_gamma[i9][i10], sArr[i10]));
            }
        }
        for (int i11 = 0; i11 < this.f1516oi; i11++) {
            for (int i12 = this.f1517vi; i12 < this.viNext; i12++) {
                short[] sArr5 = sArr2[i11];
                int i13 = this.f1517vi;
                sArr5[i12 - i13] = GF2Field.addElem(this.coeff_gamma[i11][i12], sArr5[i12 - i13]);
            }
        }
        for (int i14 = 0; i14 < this.f1516oi; i14++) {
            sArr3[i14] = GF2Field.addElem(sArr3[i14], this.coeff_eta[i14]);
        }
        while (true) {
            int i15 = this.f1516oi;
            if (i2 >= i15) {
                return sArr2;
            }
            sArr2[i2][i15] = sArr3[i2];
            i2++;
        }
    }
}