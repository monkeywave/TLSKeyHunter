package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RainbowPublicKeyParameters extends RainbowKeyParameters {
    short[][][] l1_Q3;
    short[][][] l1_Q5;
    short[][][] l1_Q6;
    short[][][] l1_Q9;
    short[][][] l2_Q9;

    /* renamed from: pk */
    short[][][] f1390pk;
    byte[] pk_seed;

    public RainbowPublicKeyParameters(RainbowParameters rainbowParameters, byte[] bArr) {
        super(false, rainbowParameters);
        int m = rainbowParameters.getM();
        int n = rainbowParameters.getN();
        if (getParameters().getVersion() != Version.CLASSIC) {
            this.pk_seed = Arrays.copyOfRange(bArr, 0, rainbowParameters.getLen_pkseed());
            this.l1_Q3 = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getO1(), rainbowParameters.getV1(), rainbowParameters.getO2());
            this.l1_Q5 = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getO1(), rainbowParameters.getO1(), rainbowParameters.getO1());
            this.l1_Q6 = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getO1(), rainbowParameters.getO1(), rainbowParameters.getO2());
            this.l1_Q9 = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getO1(), rainbowParameters.getO2(), rainbowParameters.getO2());
            this.l2_Q9 = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getO2(), rainbowParameters.getO2(), rainbowParameters.getO2());
            int len_pkseed = rainbowParameters.getLen_pkseed();
            int loadEncoded = len_pkseed + RainbowUtil.loadEncoded(this.l1_Q3, bArr, len_pkseed, false);
            int loadEncoded2 = loadEncoded + RainbowUtil.loadEncoded(this.l1_Q5, bArr, loadEncoded, true);
            int loadEncoded3 = loadEncoded2 + RainbowUtil.loadEncoded(this.l1_Q6, bArr, loadEncoded2, false);
            int loadEncoded4 = loadEncoded3 + RainbowUtil.loadEncoded(this.l1_Q9, bArr, loadEncoded3, true);
            if (loadEncoded4 + RainbowUtil.loadEncoded(this.l2_Q9, bArr, loadEncoded4, true) != bArr.length) {
                throw new IllegalArgumentException("unparsed data in key encoding");
            }
            return;
        }
        this.f1390pk = (short[][][]) Array.newInstance(Short.TYPE, m, n, n);
        int i = 0;
        for (int i2 = 0; i2 < n; i2++) {
            for (int i3 = 0; i3 < n; i3++) {
                for (int i4 = 0; i4 < m; i4++) {
                    short[][][] sArr = this.f1390pk;
                    if (i2 > i3) {
                        sArr[i4][i2][i3] = 0;
                    } else {
                        sArr[i4][i2][i3] = (short) (bArr[i] & UByte.MAX_VALUE);
                        i++;
                    }
                }
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RainbowPublicKeyParameters(RainbowParameters rainbowParameters, byte[] bArr, short[][][] sArr, short[][][] sArr2, short[][][] sArr3, short[][][] sArr4, short[][][] sArr5) {
        super(false, rainbowParameters);
        this.pk_seed = (byte[]) bArr.clone();
        this.l1_Q3 = RainbowUtil.cloneArray(sArr);
        this.l1_Q5 = RainbowUtil.cloneArray(sArr2);
        this.l1_Q6 = RainbowUtil.cloneArray(sArr3);
        this.l1_Q9 = RainbowUtil.cloneArray(sArr4);
        this.l2_Q9 = RainbowUtil.cloneArray(sArr5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RainbowPublicKeyParameters(RainbowParameters rainbowParameters, short[][][] sArr, short[][][] sArr2, short[][][] sArr3, short[][][] sArr4, short[][][] sArr5, short[][][] sArr6, short[][][] sArr7, short[][][] sArr8, short[][][] sArr9, short[][][] sArr10, short[][][] sArr11, short[][][] sArr12) {
        super(false, rainbowParameters);
        int v1 = rainbowParameters.getV1();
        int o1 = rainbowParameters.getO1();
        int o2 = rainbowParameters.getO2();
        this.f1390pk = (short[][][]) Array.newInstance(Short.TYPE, rainbowParameters.getM(), rainbowParameters.getN(), rainbowParameters.getN());
        for (int i = 0; i < o1; i++) {
            for (int i2 = 0; i2 < v1; i2++) {
                System.arraycopy(sArr[i][i2], 0, this.f1390pk[i][i2], 0, v1);
                System.arraycopy(sArr2[i][i2], 0, this.f1390pk[i][i2], v1, o1);
                System.arraycopy(sArr3[i][i2], 0, this.f1390pk[i][i2], v1 + o1, o2);
            }
            for (int i3 = 0; i3 < o1; i3++) {
                int i4 = i3 + v1;
                System.arraycopy(sArr4[i][i3], 0, this.f1390pk[i][i4], v1, o1);
                System.arraycopy(sArr5[i][i3], 0, this.f1390pk[i][i4], v1 + o1, o2);
            }
            for (int i5 = 0; i5 < o2; i5++) {
                System.arraycopy(sArr6[i][i5], 0, this.f1390pk[i][i5 + v1 + o1], v1 + o1, o2);
            }
        }
        for (int i6 = 0; i6 < o2; i6++) {
            for (int i7 = 0; i7 < v1; i7++) {
                int i8 = i6 + o1;
                System.arraycopy(sArr7[i6][i7], 0, this.f1390pk[i8][i7], 0, v1);
                System.arraycopy(sArr8[i6][i7], 0, this.f1390pk[i8][i7], v1, o1);
                System.arraycopy(sArr9[i6][i7], 0, this.f1390pk[i8][i7], v1 + o1, o2);
            }
            for (int i9 = 0; i9 < o1; i9++) {
                int i10 = i6 + o1;
                int i11 = i9 + v1;
                System.arraycopy(sArr10[i6][i9], 0, this.f1390pk[i10][i11], v1, o1);
                System.arraycopy(sArr11[i6][i9], 0, this.f1390pk[i10][i11], v1 + o1, o2);
            }
            for (int i12 = 0; i12 < o2; i12++) {
                System.arraycopy(sArr12[i6][i12], 0, this.f1390pk[i6 + o1][i12 + v1 + o1], v1 + o1, o2);
            }
        }
    }

    public byte[] getEncoded() {
        return getParameters().getVersion() != Version.CLASSIC ? Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(this.pk_seed, RainbowUtil.getEncoded(this.l1_Q3, false)), RainbowUtil.getEncoded(this.l1_Q5, true)), RainbowUtil.getEncoded(this.l1_Q6, false)), RainbowUtil.getEncoded(this.l1_Q9, true)), RainbowUtil.getEncoded(this.l2_Q9, true)) : RainbowUtil.getEncoded(this.f1390pk, true);
    }

    public short[][][] getPk() {
        return RainbowUtil.cloneArray(this.f1390pk);
    }
}