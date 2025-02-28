package org.bouncycastle.pqc.crypto.rainbow;

import java.lang.reflect.Array;
import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class RainbowSigner implements MessageSigner {
    private static final int MAXITS = 65536;

    /* renamed from: cf */
    private ComputeInField f1392cf = new ComputeInField();
    private Digest hashAlgo;
    private RainbowKeyParameters key;
    private SecureRandom random;
    int signableDocumentLength;
    private Version version;

    /* renamed from: org.bouncycastle.pqc.crypto.rainbow.RainbowSigner$1 */
    /* loaded from: classes2.dex */
    static /* synthetic */ class C13981 {
        static final /* synthetic */ int[] $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version;

        static {
            int[] iArr = new int[Version.values().length];
            $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version = iArr;
            try {
                iArr[Version.CLASSIC.ordinal()] = 1;
            } catch (NoSuchFieldError unused) {
            }
            try {
                $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[Version.CIRCUMZENITHAL.ordinal()] = 2;
            } catch (NoSuchFieldError unused2) {
            }
            try {
                $SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[Version.COMPRESSED.ordinal()] = 3;
            } catch (NoSuchFieldError unused3) {
            }
        }
    }

    private byte[] genSignature(byte[] bArr) {
        short[][] sArr;
        byte[] bArr2;
        byte[] bArr3 = new byte[this.hashAlgo.getDigestSize()];
        this.hashAlgo.update(bArr, 0, bArr.length);
        this.hashAlgo.doFinal(bArr3, 0);
        int v1 = this.key.getParameters().getV1();
        int o1 = this.key.getParameters().getO1();
        int o2 = this.key.getParameters().getO2();
        int m = this.key.getParameters().getM();
        int n = this.key.getParameters().getN();
        RainbowPrivateKeyParameters rainbowPrivateKeyParameters = (RainbowPrivateKeyParameters) this.key;
        this.random = new RainbowDRBG(RainbowUtil.hash(this.hashAlgo, rainbowPrivateKeyParameters.sk_seed, bArr3, new byte[this.hashAlgo.getDigestSize()]), rainbowPrivateKeyParameters.getParameters().getHash_algo());
        short[] sArr2 = new short[v1];
        short[] sArr3 = new short[o1];
        short[] sArr4 = new short[o2];
        short[][] sArr5 = (short[][]) Array.newInstance(Short.TYPE, o2, o1);
        short[][] sArr6 = (short[][]) Array.newInstance(Short.TYPE, o2, o2);
        byte[] bArr4 = new byte[rainbowPrivateKeyParameters.getParameters().getLen_salt()];
        short[] sArr7 = new short[o1];
        short[] sArr8 = new short[o2];
        short[] sArr9 = new short[m];
        int i = 0;
        short[][] sArr10 = null;
        while (sArr10 == null && i < 65536) {
            byte[] bArr5 = new byte[v1];
            this.random.nextBytes(bArr5);
            int i2 = 0;
            while (true) {
                bArr2 = bArr3;
                if (i2 >= v1) {
                    break;
                }
                sArr2[i2] = (short) (bArr5[i2] & UByte.MAX_VALUE);
                i2++;
                bArr3 = bArr2;
            }
            short[][] sArr11 = (short[][]) Array.newInstance(Short.TYPE, o1, o1);
            for (int i3 = 0; i3 < v1; i3++) {
                int i4 = 0;
                while (i4 < o1) {
                    byte[] bArr6 = bArr4;
                    int i5 = 0;
                    while (i5 < o1) {
                        int i6 = m;
                        short[][] sArr12 = sArr6;
                        short multElem = GF2Field.multElem(rainbowPrivateKeyParameters.l1_F2[i4][i3][i5], sArr2[i3]);
                        short[] sArr13 = sArr11[i4];
                        sArr13[i5] = GF2Field.addElem(sArr13[i5], multElem);
                        i5++;
                        m = i6;
                        sArr6 = sArr12;
                        sArr5 = sArr5;
                    }
                    i4++;
                    bArr4 = bArr6;
                }
            }
            sArr10 = this.f1392cf.inverse(sArr11);
            i++;
            bArr3 = bArr2;
            sArr6 = sArr6;
        }
        byte[] bArr7 = bArr3;
        short[][] sArr14 = sArr6;
        int i7 = m;
        short[][] sArr15 = sArr5;
        byte[] bArr8 = bArr4;
        for (int i8 = 0; i8 < o1; i8++) {
            sArr3[i8] = this.f1392cf.multiplyMatrix_quad(rainbowPrivateKeyParameters.l1_F1[i8], sArr2);
        }
        for (int i9 = 0; i9 < v1; i9++) {
            for (int i10 = 0; i10 < o2; i10++) {
                sArr4[i10] = this.f1392cf.multiplyMatrix_quad(rainbowPrivateKeyParameters.l2_F1[i10], sArr2);
                for (int i11 = 0; i11 < o1; i11++) {
                    short multElem2 = GF2Field.multElem(rainbowPrivateKeyParameters.l2_F2[i10][i9][i11], sArr2[i9]);
                    short[] sArr16 = sArr15[i10];
                    sArr16[i11] = GF2Field.addElem(sArr16[i11], multElem2);
                }
                for (int i12 = 0; i12 < o2; i12++) {
                    short multElem3 = GF2Field.multElem(rainbowPrivateKeyParameters.l2_F3[i10][i9][i12], sArr2[i9]);
                    short[] sArr17 = sArr14[i10];
                    sArr17[i12] = GF2Field.addElem(sArr17[i12], multElem3);
                }
            }
        }
        int i13 = i7;
        byte[] bArr9 = new byte[i13];
        short[] sArr18 = sArr7;
        short[] sArr19 = null;
        while (sArr19 == null && i < 65536) {
            short[][] sArr20 = (short[][]) Array.newInstance(Short.TYPE, o2, o2);
            this.random.nextBytes(bArr8);
            short[] makeMessageRepresentative = makeMessageRepresentative(RainbowUtil.hash(this.hashAlgo, bArr7, bArr8, bArr9));
            byte[] bArr10 = bArr9;
            short[] sArr21 = sArr9;
            System.arraycopy(this.f1392cf.addVect(Arrays.copyOf(makeMessageRepresentative, o1), this.f1392cf.multiplyMatrix(rainbowPrivateKeyParameters.f1386s1, Arrays.copyOfRange(makeMessageRepresentative, o1, i13))), 0, sArr21, 0, o1);
            System.arraycopy(makeMessageRepresentative, o1, sArr21, o1, o2);
            short[] multiplyMatrix = this.f1392cf.multiplyMatrix(sArr10, this.f1392cf.addVect(sArr3, Arrays.copyOf(sArr21, o1)));
            short[][] sArr22 = sArr15;
            short[] multiplyMatrix2 = this.f1392cf.multiplyMatrix(sArr22, multiplyMatrix);
            short[] sArr23 = sArr3;
            int i14 = 0;
            while (true) {
                sArr = sArr10;
                if (i14 >= o2) {
                    break;
                }
                sArr8[i14] = this.f1392cf.multiplyMatrix_quad(rainbowPrivateKeyParameters.l2_F5[i14], multiplyMatrix);
                i14++;
                sArr10 = sArr;
                sArr22 = sArr22;
            }
            sArr15 = sArr22;
            short[] sArr24 = sArr8;
            short[] addVect = this.f1392cf.addVect(this.f1392cf.addVect(this.f1392cf.addVect(multiplyMatrix2, sArr24), sArr4), Arrays.copyOfRange(sArr21, o1, i13));
            for (int i15 = 0; i15 < o1; i15++) {
                int i16 = 0;
                while (true) {
                    int i17 = i13;
                    if (i16 < o2) {
                        int i18 = 0;
                        while (i18 < o2) {
                            short[] sArr25 = sArr4;
                            short[] sArr26 = sArr24;
                            short multElem4 = GF2Field.multElem(rainbowPrivateKeyParameters.l2_F6[i16][i15][i18], multiplyMatrix[i15]);
                            short[] sArr27 = sArr20[i16];
                            sArr27[i18] = GF2Field.addElem(sArr27[i18], multElem4);
                            i18++;
                            sArr4 = sArr25;
                            sArr24 = sArr26;
                            multiplyMatrix = multiplyMatrix;
                        }
                        i16++;
                        i13 = i17;
                    }
                }
            }
            short[] sArr28 = multiplyMatrix;
            short[] sArr29 = sArr24;
            sArr19 = this.f1392cf.solveEquation(this.f1392cf.addMatrix(sArr20, sArr14), addVect);
            i++;
            sArr10 = sArr;
            bArr9 = bArr10;
            sArr3 = sArr23;
            i13 = i13;
            sArr8 = sArr29;
            sArr18 = sArr28;
            sArr9 = sArr21;
        }
        if (sArr19 == null) {
            sArr19 = new short[o2];
        }
        short[] addVect2 = this.f1392cf.addVect(this.f1392cf.addVect(sArr2, this.f1392cf.multiplyMatrix(rainbowPrivateKeyParameters.f1387t1, sArr18)), this.f1392cf.multiplyMatrix(rainbowPrivateKeyParameters.f1389t4, sArr19));
        short[] addVect3 = this.f1392cf.addVect(sArr18, this.f1392cf.multiplyMatrix(rainbowPrivateKeyParameters.f1388t3, sArr19));
        short[] copyOf = Arrays.copyOf(addVect2, n);
        System.arraycopy(addVect3, 0, copyOf, v1, o1);
        System.arraycopy(sArr19, 0, copyOf, o1 + v1, o2);
        if (i != 65536) {
            return Arrays.concatenate(RainbowUtil.convertArray(copyOf), bArr8);
        }
        throw new IllegalStateException("unable to generate signature - LES not solvable");
    }

    private short[] makeMessageRepresentative(byte[] bArr) {
        int i = this.signableDocumentLength;
        short[] sArr = new short[i];
        int i2 = 0;
        int i3 = 0;
        while (i2 < bArr.length) {
            sArr[i2] = (short) (bArr[i3] & UByte.MAX_VALUE);
            i3++;
            i2++;
            if (i2 >= i) {
                break;
            }
        }
        return sArr;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        return genSignature(bArr);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        RainbowKeyParameters rainbowKeyParameters;
        if (z) {
            if (cipherParameters instanceof ParametersWithRandom) {
                ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
                this.random = parametersWithRandom.getRandom();
                rainbowKeyParameters = (RainbowKeyParameters) parametersWithRandom.getParameters();
            } else {
                rainbowKeyParameters = (RainbowKeyParameters) cipherParameters;
                SecureRandom secureRandom = CryptoServicesRegistrar.getSecureRandom();
                byte[] bArr = new byte[rainbowKeyParameters.getParameters().getLen_skseed()];
                secureRandom.nextBytes(bArr);
                this.random = new RainbowDRBG(bArr, rainbowKeyParameters.getParameters().getHash_algo());
            }
            this.version = rainbowKeyParameters.getParameters().getVersion();
            this.key = rainbowKeyParameters;
        } else {
            RainbowKeyParameters rainbowKeyParameters2 = (RainbowKeyParameters) cipherParameters;
            this.key = rainbowKeyParameters2;
            this.version = rainbowKeyParameters2.getParameters().getVersion();
        }
        this.signableDocumentLength = this.key.getDocLength();
        this.hashAlgo = this.key.getParameters().getHash_algo();
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        short[] publicMap;
        byte[] bArr3 = new byte[this.hashAlgo.getDigestSize()];
        this.hashAlgo.update(bArr, 0, bArr.length);
        this.hashAlgo.doFinal(bArr3, 0);
        int m = this.key.getParameters().getM();
        int n = this.key.getParameters().getN();
        RainbowPublicMap rainbowPublicMap = new RainbowPublicMap(this.key.getParameters());
        short[] makeMessageRepresentative = makeMessageRepresentative(RainbowUtil.hash(this.hashAlgo, bArr3, Arrays.copyOfRange(bArr2, n, bArr2.length), new byte[m]));
        short[] convertArray = RainbowUtil.convertArray(Arrays.copyOfRange(bArr2, 0, n));
        int i = C13981.$SwitchMap$org$bouncycastle$pqc$crypto$rainbow$Version[this.version.ordinal()];
        if (i == 1) {
            publicMap = rainbowPublicMap.publicMap((RainbowPublicKeyParameters) this.key, convertArray);
        } else if (i != 2 && i != 3) {
            throw new IllegalArgumentException("No valid version. Please choose one of the following: classic, circumzenithal, compressed");
        } else {
            publicMap = rainbowPublicMap.publicMap_cyclic((RainbowPublicKeyParameters) this.key, convertArray);
        }
        return RainbowUtil.equals(makeMessageRepresentative, publicMap);
    }
}