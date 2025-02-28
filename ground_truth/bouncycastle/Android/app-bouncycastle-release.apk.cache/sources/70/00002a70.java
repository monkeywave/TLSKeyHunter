package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class RainbowPublicMap {
    private RainbowParameters params;
    private final int num_gf_elements = 256;

    /* renamed from: cf */
    private ComputeInField f1391cf = new ComputeInField();

    public RainbowPublicMap(RainbowParameters rainbowParameters) {
        this.params = rainbowParameters;
    }

    private short[] add_and_reduce(short[][] sArr) {
        int m = this.params.getM();
        short[] sArr2 = new short[m];
        for (int i = 0; i < 8; i++) {
            int pow = (int) Math.pow(2.0d, i);
            short[] sArr3 = new short[m];
            for (int i2 = pow; i2 < 256; i2 += pow * 2) {
                for (int i3 = 0; i3 < pow; i3++) {
                    sArr3 = this.f1391cf.addVect(sArr3, sArr[i2 + i3]);
                }
            }
            ComputeInField computeInField = this.f1391cf;
            sArr2 = computeInField.addVect(sArr2, computeInField.multVect((short) pow, sArr3));
        }
        return sArr2;
    }

    private short[][] compute_accumulator(short[] sArr, short[] sArr2, short[][][] sArr3, int i) {
        short[][] sArr4 = (short[][]) Array.newInstance(Short.TYPE, 256, i);
        int length = sArr2.length;
        short[][] sArr5 = sArr3[0];
        if (length == sArr5.length && sArr.length == sArr5[0].length && sArr3.length == i) {
            for (int i2 = 0; i2 < sArr2.length; i2++) {
                short[] multVect = this.f1391cf.multVect(sArr2[i2], sArr);
                for (int i3 = 0; i3 < sArr.length; i3++) {
                    for (int i4 = 0; i4 < sArr3.length; i4++) {
                        short s = multVect[i3];
                        if (s != 0) {
                            short[] sArr6 = sArr4[s];
                            sArr6[i4] = GF2Field.addElem(sArr6[i4], sArr3[i4][i2][i3]);
                        }
                    }
                }
            }
            return sArr4;
        }
        throw new RuntimeException("Accumulator calculation not possible!");
    }

    public short[] publicMap(RainbowPublicKeyParameters rainbowPublicKeyParameters, short[] sArr) {
        return add_and_reduce(compute_accumulator(sArr, sArr, rainbowPublicKeyParameters.f1390pk, this.params.getM()));
    }

    public short[] publicMap_cyclic(RainbowPublicKeyParameters rainbowPublicKeyParameters, short[] sArr) {
        int v1 = this.params.getV1();
        int o1 = this.params.getO1();
        int o2 = this.params.getO2();
        short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, 256, o1 + o2);
        short[] copyOfRange = Arrays.copyOfRange(sArr, 0, v1);
        int i = v1 + o1;
        short[] copyOfRange2 = Arrays.copyOfRange(sArr, v1, i);
        short[] copyOfRange3 = Arrays.copyOfRange(sArr, i, sArr.length);
        RainbowDRBG rainbowDRBG = new RainbowDRBG(rainbowPublicKeyParameters.pk_seed, rainbowPublicKeyParameters.getParameters().getHash_algo());
        short[][] addMatrix = this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(compute_accumulator(copyOfRange, copyOfRange, RainbowUtil.generate_random(rainbowDRBG, o1, v1, v1, true), o1), compute_accumulator(copyOfRange2, copyOfRange, RainbowUtil.generate_random(rainbowDRBG, o1, v1, o1, false), o1)), compute_accumulator(copyOfRange3, copyOfRange, rainbowPublicKeyParameters.l1_Q3, o1)), compute_accumulator(copyOfRange2, copyOfRange2, rainbowPublicKeyParameters.l1_Q5, o1)), compute_accumulator(copyOfRange3, copyOfRange2, rainbowPublicKeyParameters.l1_Q6, o1)), compute_accumulator(copyOfRange3, copyOfRange3, rainbowPublicKeyParameters.l1_Q9, o1));
        short[][] addMatrix2 = this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(this.f1391cf.addMatrix(compute_accumulator(copyOfRange, copyOfRange, RainbowUtil.generate_random(rainbowDRBG, o2, v1, v1, true), o2), compute_accumulator(copyOfRange2, copyOfRange, RainbowUtil.generate_random(rainbowDRBG, o2, v1, o1, false), o2)), compute_accumulator(copyOfRange3, copyOfRange, RainbowUtil.generate_random(rainbowDRBG, o2, v1, o2, false), o2)), compute_accumulator(copyOfRange2, copyOfRange2, RainbowUtil.generate_random(rainbowDRBG, o2, o1, o1, true), o2)), compute_accumulator(copyOfRange3, copyOfRange2, RainbowUtil.generate_random(rainbowDRBG, o2, o1, o2, false), o2)), compute_accumulator(copyOfRange3, copyOfRange3, rainbowPublicKeyParameters.l2_Q9, o2));
        for (int i2 = 0; i2 < 256; i2++) {
            sArr2[i2] = Arrays.concatenate(addMatrix[i2], addMatrix2[i2]);
        }
        return add_and_reduce(sArr2);
    }
}