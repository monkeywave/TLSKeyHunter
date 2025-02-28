package org.bouncycastle.pqc.crypto.rainbow;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;
import org.bouncycastle.pqc.crypto.rainbow.util.ComputeInField;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/rainbow/RainbowSigner.class */
public class RainbowSigner implements MessageSigner {
    private static final int MAXITS = 65536;
    private SecureRandom random;
    int signableDocumentLength;

    /* renamed from: x */
    private short[] f906x;

    /* renamed from: cf */
    private ComputeInField f907cf = new ComputeInField();
    RainbowKeyParameters key;

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!z) {
            this.key = (RainbowPublicKeyParameters) cipherParameters;
        } else if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.random = parametersWithRandom.getRandom();
            this.key = (RainbowPrivateKeyParameters) parametersWithRandom.getParameters();
        } else {
            this.random = CryptoServicesRegistrar.getSecureRandom();
            this.key = (RainbowPrivateKeyParameters) cipherParameters;
        }
        this.signableDocumentLength = this.key.getDocLength();
    }

    private short[] initSign(Layer[] layerArr, short[] sArr) {
        short[] sArr2 = new short[sArr.length];
        short[] multiplyMatrix = this.f907cf.multiplyMatrix(((RainbowPrivateKeyParameters) this.key).getInvA1(), this.f907cf.addVect(((RainbowPrivateKeyParameters) this.key).getB1(), sArr));
        for (int i = 0; i < layerArr[0].getVi(); i++) {
            this.f906x[i] = (short) this.random.nextInt();
            this.f906x[i] = (short) (this.f906x[i] & 255);
        }
        return multiplyMatrix;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        Layer[] layers = ((RainbowPrivateKeyParameters) this.key).getLayers();
        int length = layers.length;
        this.f906x = new short[((RainbowPrivateKeyParameters) this.key).getInvA2().length];
        byte[] bArr2 = new byte[layers[length - 1].getViNext()];
        short[] makeMessageRepresentative = makeMessageRepresentative(bArr);
        int i = 0;
        do {
            boolean z = true;
            int i2 = 0;
            try {
                short[] initSign = initSign(layers, makeMessageRepresentative);
                for (int i3 = 0; i3 < length; i3++) {
                    short[] sArr = new short[layers[i3].getOi()];
                    short[] sArr2 = new short[layers[i3].getOi()];
                    for (int i4 = 0; i4 < layers[i3].getOi(); i4++) {
                        sArr[i4] = initSign[i2];
                        i2++;
                    }
                    short[] solveEquation = this.f907cf.solveEquation(layers[i3].plugInVinegars(this.f906x), sArr);
                    if (solveEquation == null) {
                        throw new Exception("LES is not solveable!");
                        break;
                    }
                    for (int i5 = 0; i5 < solveEquation.length; i5++) {
                        this.f906x[layers[i3].getVi() + i5] = solveEquation[i5];
                    }
                }
                short[] multiplyMatrix = this.f907cf.multiplyMatrix(((RainbowPrivateKeyParameters) this.key).getInvA2(), this.f907cf.addVect(((RainbowPrivateKeyParameters) this.key).getB2(), this.f906x));
                for (int i6 = 0; i6 < bArr2.length; i6++) {
                    bArr2[i6] = (byte) multiplyMatrix[i6];
                }
            } catch (Exception e) {
                z = false;
            }
            if (z) {
                break;
            }
            i++;
        } while (i < 65536);
        if (i == 65536) {
            throw new IllegalStateException("unable to generate signature - LES not solvable");
        }
        return bArr2;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        short[] sArr = new short[bArr2.length];
        for (int i = 0; i < bArr2.length; i++) {
            sArr[i] = (short) (bArr2[i] & 255);
        }
        short[] makeMessageRepresentative = makeMessageRepresentative(bArr);
        short[] verifySignatureIntern = verifySignatureIntern(sArr);
        boolean z = true;
        if (makeMessageRepresentative.length != verifySignatureIntern.length) {
            return false;
        }
        for (int i2 = 0; i2 < makeMessageRepresentative.length; i2++) {
            z = z && makeMessageRepresentative[i2] == verifySignatureIntern[i2];
        }
        return z;
    }

    private short[] verifySignatureIntern(short[] sArr) {
        short[][] coeffQuadratic = ((RainbowPublicKeyParameters) this.key).getCoeffQuadratic();
        short[][] coeffSingular = ((RainbowPublicKeyParameters) this.key).getCoeffSingular();
        short[] coeffScalar = ((RainbowPublicKeyParameters) this.key).getCoeffScalar();
        short[] sArr2 = new short[coeffQuadratic.length];
        int length = coeffSingular[0].length;
        for (int i = 0; i < coeffQuadratic.length; i++) {
            int i2 = 0;
            for (int i3 = 0; i3 < length; i3++) {
                for (int i4 = i3; i4 < length; i4++) {
                    sArr2[i] = GF2Field.addElem(sArr2[i], GF2Field.multElem(coeffQuadratic[i][i2], GF2Field.multElem(sArr[i3], sArr[i4])));
                    i2++;
                }
                sArr2[i] = GF2Field.addElem(sArr2[i], GF2Field.multElem(coeffSingular[i][i3], sArr[i3]));
            }
            sArr2[i] = GF2Field.addElem(sArr2[i], coeffScalar[i]);
        }
        return sArr2;
    }

    private short[] makeMessageRepresentative(byte[] bArr) {
        short[] sArr = new short[this.signableDocumentLength];
        int i = 0;
        int i2 = 0;
        while (i2 < bArr.length) {
            sArr[i2] = bArr[i];
            int i3 = i2;
            sArr[i3] = (short) (sArr[i3] & 255);
            i++;
            i2++;
            if (i2 >= sArr.length) {
                break;
            }
        }
        return sArr;
    }
}