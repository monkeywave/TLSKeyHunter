package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/RainbowKeyPairGenerator.class */
public class RainbowKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private boolean initialized = false;

    /* renamed from: sr */
    private SecureRandom f896sr;
    private RainbowKeyGenerationParameters rainbowParams;

    /* renamed from: A1 */
    private short[][] f897A1;
    private short[][] A1inv;

    /* renamed from: b1 */
    private short[] f898b1;

    /* renamed from: A2 */
    private short[][] f899A2;
    private short[][] A2inv;

    /* renamed from: b2 */
    private short[] f900b2;
    private int numOfLayers;
    private Layer[] layers;

    /* renamed from: vi */
    private int[] f901vi;
    private short[][] pub_quadratic;
    private short[][] pub_singular;
    private short[] pub_scalar;

    public AsymmetricCipherKeyPair genKeyPair() {
        if (!this.initialized) {
            initializeDefault();
        }
        keygen();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new RainbowPublicKeyParameters(this.f901vi[this.f901vi.length - 1] - this.f901vi[0], this.pub_quadratic, this.pub_singular, this.pub_scalar), (AsymmetricKeyParameter) new RainbowPrivateKeyParameters(this.A1inv, this.f898b1, this.A2inv, this.f900b2, this.f901vi, this.layers));
    }

    public void initialize(KeyGenerationParameters keyGenerationParameters) {
        this.rainbowParams = (RainbowKeyGenerationParameters) keyGenerationParameters;
        this.f896sr = this.rainbowParams.getRandom();
        this.f901vi = this.rainbowParams.getParameters().getVi();
        this.numOfLayers = this.rainbowParams.getParameters().getNumOfLayers();
        this.initialized = true;
    }

    private void initializeDefault() {
        initialize(new RainbowKeyGenerationParameters(CryptoServicesRegistrar.getSecureRandom(), new RainbowParameters()));
    }

    private void keygen() {
        generateL1();
        generateL2();
        generateF();
        computePublicKey();
    }

    private void generateL1() {
        int i = this.f901vi[this.f901vi.length - 1] - this.f901vi[0];
        this.f897A1 = new short[i][i];
        this.A1inv = null;
        ComputeInField computeInField = new ComputeInField();
        while (this.A1inv == null) {
            for (int i2 = 0; i2 < i; i2++) {
                for (int i3 = 0; i3 < i; i3++) {
                    this.f897A1[i2][i3] = (short) (this.f896sr.nextInt() & GF2Field.MASK);
                }
            }
            this.A1inv = computeInField.inverse(this.f897A1);
        }
        this.f898b1 = new short[i];
        for (int i4 = 0; i4 < i; i4++) {
            this.f898b1[i4] = (short) (this.f896sr.nextInt() & GF2Field.MASK);
        }
    }

    private void generateL2() {
        int i = this.f901vi[this.f901vi.length - 1];
        this.f899A2 = new short[i][i];
        this.A2inv = null;
        ComputeInField computeInField = new ComputeInField();
        while (this.A2inv == null) {
            for (int i2 = 0; i2 < i; i2++) {
                for (int i3 = 0; i3 < i; i3++) {
                    this.f899A2[i2][i3] = (short) (this.f896sr.nextInt() & GF2Field.MASK);
                }
            }
            this.A2inv = computeInField.inverse(this.f899A2);
        }
        this.f900b2 = new short[i];
        for (int i4 = 0; i4 < i; i4++) {
            this.f900b2[i4] = (short) (this.f896sr.nextInt() & GF2Field.MASK);
        }
    }

    private void generateF() {
        this.layers = new Layer[this.numOfLayers];
        for (int i = 0; i < this.numOfLayers; i++) {
            this.layers[i] = new Layer(this.f901vi[i], this.f901vi[i + 1], this.f896sr);
        }
    }

    private void computePublicKey() {
        ComputeInField computeInField = new ComputeInField();
        int i = this.f901vi[this.f901vi.length - 1] - this.f901vi[0];
        int i2 = this.f901vi[this.f901vi.length - 1];
        short[][][] sArr = new short[i][i2][i2];
        this.pub_singular = new short[i][i2];
        this.pub_scalar = new short[i];
        int i3 = 0;
        short[] sArr2 = new short[i2];
        for (int i4 = 0; i4 < this.layers.length; i4++) {
            short[][][] coeffAlpha = this.layers[i4].getCoeffAlpha();
            short[][][] coeffBeta = this.layers[i4].getCoeffBeta();
            short[][] coeffGamma = this.layers[i4].getCoeffGamma();
            short[] coeffEta = this.layers[i4].getCoeffEta();
            int length = coeffAlpha[0].length;
            int length2 = coeffBeta[0].length;
            for (int i5 = 0; i5 < length; i5++) {
                for (int i6 = 0; i6 < length; i6++) {
                    for (int i7 = 0; i7 < length2; i7++) {
                        short[] multVect = computeInField.multVect(coeffAlpha[i5][i6][i7], this.f899A2[i6 + length2]);
                        sArr[i3 + i5] = computeInField.addSquareMatrix(sArr[i3 + i5], computeInField.multVects(multVect, this.f899A2[i7]));
                        this.pub_singular[i3 + i5] = computeInField.addVect(computeInField.multVect(this.f900b2[i7], multVect), this.pub_singular[i3 + i5]);
                        this.pub_singular[i3 + i5] = computeInField.addVect(computeInField.multVect(this.f900b2[i6 + length2], computeInField.multVect(coeffAlpha[i5][i6][i7], this.f899A2[i7])), this.pub_singular[i3 + i5]);
                        this.pub_scalar[i3 + i5] = GF2Field.addElem(this.pub_scalar[i3 + i5], GF2Field.multElem(GF2Field.multElem(coeffAlpha[i5][i6][i7], this.f900b2[i6 + length2]), this.f900b2[i7]));
                    }
                }
                for (int i8 = 0; i8 < length2; i8++) {
                    for (int i9 = 0; i9 < length2; i9++) {
                        short[] multVect2 = computeInField.multVect(coeffBeta[i5][i8][i9], this.f899A2[i8]);
                        sArr[i3 + i5] = computeInField.addSquareMatrix(sArr[i3 + i5], computeInField.multVects(multVect2, this.f899A2[i9]));
                        this.pub_singular[i3 + i5] = computeInField.addVect(computeInField.multVect(this.f900b2[i9], multVect2), this.pub_singular[i3 + i5]);
                        this.pub_singular[i3 + i5] = computeInField.addVect(computeInField.multVect(this.f900b2[i8], computeInField.multVect(coeffBeta[i5][i8][i9], this.f899A2[i9])), this.pub_singular[i3 + i5]);
                        this.pub_scalar[i3 + i5] = GF2Field.addElem(this.pub_scalar[i3 + i5], GF2Field.multElem(GF2Field.multElem(coeffBeta[i5][i8][i9], this.f900b2[i8]), this.f900b2[i9]));
                    }
                }
                for (int i10 = 0; i10 < length2 + length; i10++) {
                    this.pub_singular[i3 + i5] = computeInField.addVect(computeInField.multVect(coeffGamma[i5][i10], this.f899A2[i10]), this.pub_singular[i3 + i5]);
                    this.pub_scalar[i3 + i5] = GF2Field.addElem(this.pub_scalar[i3 + i5], GF2Field.multElem(coeffGamma[i5][i10], this.f900b2[i10]));
                }
                this.pub_scalar[i3 + i5] = GF2Field.addElem(this.pub_scalar[i3 + i5], coeffEta[i5]);
            }
            i3 += length;
        }
        short[][][] sArr3 = new short[i][i2][i2];
        short[][] sArr4 = new short[i][i2];
        short[] sArr5 = new short[i];
        for (int i11 = 0; i11 < i; i11++) {
            for (int i12 = 0; i12 < this.f897A1.length; i12++) {
                sArr3[i11] = computeInField.addSquareMatrix(sArr3[i11], computeInField.multMatrix(this.f897A1[i11][i12], sArr[i12]));
                sArr4[i11] = computeInField.addVect(sArr4[i11], computeInField.multVect(this.f897A1[i11][i12], this.pub_singular[i12]));
                sArr5[i11] = GF2Field.addElem(sArr5[i11], GF2Field.multElem(this.f897A1[i11][i12], this.pub_scalar[i12]));
            }
            sArr5[i11] = GF2Field.addElem(sArr5[i11], this.f898b1[i11]);
        }
        this.pub_singular = sArr4;
        this.pub_scalar = sArr5;
        compactPublicKey(sArr3);
    }

    private void compactPublicKey(short[][][] sArr) {
        int length = sArr.length;
        int length2 = sArr[0].length;
        this.pub_quadratic = new short[length][(length2 * (length2 + 1)) / 2];
        for (int i = 0; i < length; i++) {
            int i2 = 0;
            for (int i3 = 0; i3 < length2; i3++) {
                for (int i4 = i3; i4 < length2; i4++) {
                    if (i4 == i3) {
                        this.pub_quadratic[i][i2] = sArr[i][i3][i4];
                    } else {
                        this.pub_quadratic[i][i2] = GF2Field.addElem(sArr[i][i3][i4], sArr[i][i4][i3]);
                    }
                    i2++;
                }
            }
        }
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        initialize(keyGenerationParameters);
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        return genKeyPair();
    }
}