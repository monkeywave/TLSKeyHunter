package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RainbowPrivateKeyParameters extends RainbowKeyParameters {
    final short[][][] l1_F1;
    final short[][][] l1_F2;
    final short[][][] l2_F1;
    final short[][][] l2_F2;
    final short[][][] l2_F3;
    final short[][][] l2_F5;
    final short[][][] l2_F6;
    private byte[] pk_encoded;
    private final byte[] pk_seed;

    /* renamed from: s1 */
    final short[][] f1386s1;
    final byte[] sk_seed;

    /* renamed from: t1 */
    final short[][] f1387t1;

    /* renamed from: t3 */
    final short[][] f1388t3;

    /* renamed from: t4 */
    final short[][] f1389t4;

    public RainbowPrivateKeyParameters(RainbowParameters rainbowParameters, byte[] bArr) {
        super(true, rainbowParameters);
        if (rainbowParameters.getVersion() == Version.COMPRESSED) {
            byte[] copyOfRange = Arrays.copyOfRange(bArr, 0, rainbowParameters.getLen_pkseed());
            this.pk_seed = copyOfRange;
            byte[] copyOfRange2 = Arrays.copyOfRange(bArr, rainbowParameters.getLen_pkseed(), rainbowParameters.getLen_pkseed() + rainbowParameters.getLen_skseed());
            this.sk_seed = copyOfRange2;
            RainbowPrivateKeyParameters generatePrivateKey = new RainbowKeyComputation(rainbowParameters, copyOfRange, copyOfRange2).generatePrivateKey();
            this.pk_encoded = generatePrivateKey.pk_encoded;
            this.f1386s1 = generatePrivateKey.f1386s1;
            this.f1387t1 = generatePrivateKey.f1387t1;
            this.f1388t3 = generatePrivateKey.f1388t3;
            this.f1389t4 = generatePrivateKey.f1389t4;
            this.l1_F1 = generatePrivateKey.l1_F1;
            this.l1_F2 = generatePrivateKey.l1_F2;
            this.l2_F1 = generatePrivateKey.l2_F1;
            this.l2_F2 = generatePrivateKey.l2_F2;
            this.l2_F3 = generatePrivateKey.l2_F3;
            this.l2_F5 = generatePrivateKey.l2_F5;
            this.l2_F6 = generatePrivateKey.l2_F6;
            return;
        }
        int v1 = rainbowParameters.getV1();
        int o1 = rainbowParameters.getO1();
        int o2 = rainbowParameters.getO2();
        short[][] sArr = (short[][]) Array.newInstance(Short.TYPE, o1, o2);
        this.f1386s1 = sArr;
        short[][] sArr2 = (short[][]) Array.newInstance(Short.TYPE, v1, o1);
        this.f1387t1 = sArr2;
        short[][] sArr3 = (short[][]) Array.newInstance(Short.TYPE, v1, o2);
        this.f1389t4 = sArr3;
        short[][] sArr4 = (short[][]) Array.newInstance(Short.TYPE, o1, o2);
        this.f1388t3 = sArr4;
        short[][][] sArr5 = (short[][][]) Array.newInstance(Short.TYPE, o1, v1, v1);
        this.l1_F1 = sArr5;
        short[][][] sArr6 = (short[][][]) Array.newInstance(Short.TYPE, o1, v1, o1);
        this.l1_F2 = sArr6;
        short[][][] sArr7 = (short[][][]) Array.newInstance(Short.TYPE, o2, v1, v1);
        this.l2_F1 = sArr7;
        short[][][] sArr8 = (short[][][]) Array.newInstance(Short.TYPE, o2, v1, o1);
        this.l2_F2 = sArr8;
        short[][][] sArr9 = (short[][][]) Array.newInstance(Short.TYPE, o2, v1, o2);
        this.l2_F3 = sArr9;
        short[][][] sArr10 = (short[][][]) Array.newInstance(Short.TYPE, o2, o1, o1);
        this.l2_F5 = sArr10;
        short[][][] sArr11 = (short[][][]) Array.newInstance(Short.TYPE, o2, o1, o2);
        this.l2_F6 = sArr11;
        this.pk_seed = null;
        byte[] copyOfRange3 = Arrays.copyOfRange(bArr, 0, rainbowParameters.getLen_skseed());
        this.sk_seed = copyOfRange3;
        int length = copyOfRange3.length;
        int loadEncoded = length + RainbowUtil.loadEncoded(sArr, bArr, length);
        int loadEncoded2 = loadEncoded + RainbowUtil.loadEncoded(sArr2, bArr, loadEncoded);
        int loadEncoded3 = loadEncoded2 + RainbowUtil.loadEncoded(sArr3, bArr, loadEncoded2);
        int loadEncoded4 = loadEncoded3 + RainbowUtil.loadEncoded(sArr4, bArr, loadEncoded3);
        int loadEncoded5 = loadEncoded4 + RainbowUtil.loadEncoded(sArr5, bArr, loadEncoded4, true);
        int loadEncoded6 = loadEncoded5 + RainbowUtil.loadEncoded(sArr6, bArr, loadEncoded5, false);
        int loadEncoded7 = loadEncoded6 + RainbowUtil.loadEncoded(sArr7, bArr, loadEncoded6, true);
        int loadEncoded8 = loadEncoded7 + RainbowUtil.loadEncoded(sArr8, bArr, loadEncoded7, false);
        int loadEncoded9 = loadEncoded8 + RainbowUtil.loadEncoded(sArr9, bArr, loadEncoded8, false);
        int loadEncoded10 = loadEncoded9 + RainbowUtil.loadEncoded(sArr10, bArr, loadEncoded9, true);
        this.pk_encoded = Arrays.copyOfRange(bArr, loadEncoded10 + RainbowUtil.loadEncoded(sArr11, bArr, loadEncoded10, false), bArr.length);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RainbowPrivateKeyParameters(RainbowParameters rainbowParameters, byte[] bArr, byte[] bArr2, byte[] bArr3) {
        super(true, rainbowParameters);
        RainbowPrivateKeyParameters generatePrivateKey = new RainbowKeyComputation(rainbowParameters, bArr, bArr2).generatePrivateKey();
        this.pk_seed = bArr;
        this.pk_encoded = bArr3;
        this.sk_seed = bArr2;
        this.f1386s1 = generatePrivateKey.f1386s1;
        this.f1387t1 = generatePrivateKey.f1387t1;
        this.f1388t3 = generatePrivateKey.f1388t3;
        this.f1389t4 = generatePrivateKey.f1389t4;
        this.l1_F1 = generatePrivateKey.l1_F1;
        this.l1_F2 = generatePrivateKey.l1_F2;
        this.l2_F1 = generatePrivateKey.l2_F1;
        this.l2_F2 = generatePrivateKey.l2_F2;
        this.l2_F3 = generatePrivateKey.l2_F3;
        this.l2_F5 = generatePrivateKey.l2_F5;
        this.l2_F6 = generatePrivateKey.l2_F6;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public RainbowPrivateKeyParameters(RainbowParameters rainbowParameters, byte[] bArr, short[][] sArr, short[][] sArr2, short[][] sArr3, short[][] sArr4, short[][][] sArr5, short[][][] sArr6, short[][][] sArr7, short[][][] sArr8, short[][][] sArr9, short[][][] sArr10, short[][][] sArr11, byte[] bArr2) {
        super(true, rainbowParameters);
        this.pk_seed = null;
        this.pk_encoded = bArr2;
        this.sk_seed = (byte[]) bArr.clone();
        this.f1386s1 = RainbowUtil.cloneArray(sArr);
        this.f1387t1 = RainbowUtil.cloneArray(sArr2);
        this.f1388t3 = RainbowUtil.cloneArray(sArr3);
        this.f1389t4 = RainbowUtil.cloneArray(sArr4);
        this.l1_F1 = RainbowUtil.cloneArray(sArr5);
        this.l1_F2 = RainbowUtil.cloneArray(sArr6);
        this.l2_F1 = RainbowUtil.cloneArray(sArr7);
        this.l2_F2 = RainbowUtil.cloneArray(sArr8);
        this.l2_F3 = RainbowUtil.cloneArray(sArr9);
        this.l2_F5 = RainbowUtil.cloneArray(sArr10);
        this.l2_F6 = RainbowUtil.cloneArray(sArr11);
    }

    public byte[] getEncoded() {
        return getParameters().getVersion() == Version.COMPRESSED ? Arrays.concatenate(this.pk_seed, this.sk_seed) : Arrays.concatenate(getPrivateKey(), this.pk_encoded);
    }

    short[][][] getL1_F1() {
        return RainbowUtil.cloneArray(this.l1_F1);
    }

    short[][][] getL1_F2() {
        return RainbowUtil.cloneArray(this.l1_F2);
    }

    short[][][] getL2_F1() {
        return RainbowUtil.cloneArray(this.l2_F1);
    }

    short[][][] getL2_F2() {
        return RainbowUtil.cloneArray(this.l2_F2);
    }

    short[][][] getL2_F3() {
        return RainbowUtil.cloneArray(this.l2_F3);
    }

    short[][][] getL2_F5() {
        return RainbowUtil.cloneArray(this.l2_F5);
    }

    short[][][] getL2_F6() {
        return RainbowUtil.cloneArray(this.l2_F6);
    }

    public byte[] getPrivateKey() {
        return getParameters().getVersion() == Version.COMPRESSED ? Arrays.concatenate(this.pk_seed, this.sk_seed) : Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(Arrays.concatenate(this.sk_seed, RainbowUtil.getEncoded(this.f1386s1)), RainbowUtil.getEncoded(this.f1387t1)), RainbowUtil.getEncoded(this.f1389t4)), RainbowUtil.getEncoded(this.f1388t3)), RainbowUtil.getEncoded(this.l1_F1, true)), RainbowUtil.getEncoded(this.l1_F2, false)), RainbowUtil.getEncoded(this.l2_F1, true)), RainbowUtil.getEncoded(this.l2_F2, false)), RainbowUtil.getEncoded(this.l2_F3, false)), RainbowUtil.getEncoded(this.l2_F5, true)), RainbowUtil.getEncoded(this.l2_F6, false));
    }

    public byte[] getPublicKey() {
        return this.pk_encoded;
    }

    short[][] getS1() {
        return RainbowUtil.cloneArray(this.f1386s1);
    }

    byte[] getSk_seed() {
        return Arrays.clone(this.sk_seed);
    }

    short[][] getT1() {
        return RainbowUtil.cloneArray(this.f1387t1);
    }

    short[][] getT3() {
        return RainbowUtil.cloneArray(this.f1388t3);
    }

    short[][] getT4() {
        return RainbowUtil.cloneArray(this.f1389t4);
    }
}