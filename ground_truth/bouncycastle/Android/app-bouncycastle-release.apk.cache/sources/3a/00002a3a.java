package org.bouncycastle.pqc.crypto.ntruprime;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class NTRULPRimeKEMExtractor implements EncapsulatedSecretExtractor {
    private final NTRULPRimePrivateKeyParameters privateKey;

    public NTRULPRimeKEMExtractor(NTRULPRimePrivateKeyParameters nTRULPRimePrivateKeyParameters) {
        this.privateKey = nTRULPRimePrivateKeyParameters;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretExtractor
    public byte[] extractSecret(byte[] bArr) {
        NTRULPRimeParameters parameters = this.privateKey.getParameters();
        int p = parameters.getP();
        int q = parameters.getQ();
        int w = parameters.getW();
        int roundedPolynomialBytes = parameters.getRoundedPolynomialBytes();
        int tau0 = parameters.getTau0();
        int tau1 = parameters.getTau1();
        int tau2 = parameters.getTau2();
        int tau3 = parameters.getTau3();
        byte[] bArr2 = new byte[p];
        Utils.getDecodedSmallPolynomial(bArr2, this.privateKey.getEncoded(), p);
        byte[] bArr3 = new byte[roundedPolynomialBytes];
        System.arraycopy(bArr, 0, bArr3, 0, roundedPolynomialBytes);
        short[] sArr = new short[p];
        Utils.getRoundedDecodedPolynomial(sArr, bArr3, p, q);
        byte[] bArr4 = new byte[128];
        System.arraycopy(bArr, roundedPolynomialBytes, bArr4, 0, 128);
        byte[] bArr5 = new byte[256];
        Utils.getTopDecodedPolynomial(bArr5, bArr4);
        short[] sArr2 = new short[p];
        Utils.multiplicationInRQ(sArr2, sArr, bArr2, p, q);
        byte[] bArr6 = new byte[256];
        Utils.right(bArr6, sArr2, bArr5, q, w, tau2, tau3);
        byte[] bArr7 = new byte[32];
        Utils.getEncodedInputs(bArr7, bArr6);
        int publicKeyBytes = parameters.getPublicKeyBytes() - 32;
        byte[] bArr8 = new byte[publicKeyBytes];
        System.arraycopy(this.privateKey.getPk(), 32, bArr8, 0, publicKeyBytes);
        short[] sArr3 = new short[p];
        Utils.getRoundedDecodedPolynomial(sArr3, bArr8, p, q);
        byte[] bArr9 = new byte[32];
        System.arraycopy(this.privateKey.getPk(), 0, bArr9, 0, 32);
        short[] sArr4 = new short[p];
        Utils.generatePolynomialInRQFromSeed(sArr4, bArr9, p, q);
        byte[] hashWithPrefix = Utils.getHashWithPrefix(new byte[]{5}, bArr7);
        int[] iArr = new int[p];
        Utils.expand(iArr, Arrays.copyOfRange(hashWithPrefix, 0, hashWithPrefix.length / 2));
        byte[] bArr10 = new byte[p];
        Utils.sortGenerateShortPolynomial(bArr10, iArr, p, w);
        short[] sArr5 = new short[p];
        Utils.multiplicationInRQ(sArr5, sArr4, bArr10, p, q);
        short[] sArr6 = new short[p];
        Utils.roundPolynomial(sArr6, sArr5);
        Utils.getRoundedEncodedPolynomial(new byte[roundedPolynomialBytes], sArr6, p, q);
        short[] sArr7 = new short[p];
        Utils.multiplicationInRQ(sArr7, sArr3, bArr10, p, q);
        Utils.top(new byte[256], sArr7, bArr6, q, tau0, tau1);
        Utils.getTopEncodedPolynomial(new byte[128], bArr5);
        byte[] bArr11 = new byte[this.privateKey.getHash().length + 32];
        System.arraycopy(bArr7, 0, bArr11, 0, 32);
        System.arraycopy(this.privateKey.getHash(), 0, bArr11, 32, this.privateKey.getHash().length);
        byte[] hashWithPrefix2 = Utils.getHashWithPrefix(new byte[]{2}, bArr11);
        int i = roundedPolynomialBytes + 128;
        int length = (hashWithPrefix2.length / 2) + i;
        byte[] bArr12 = new byte[length];
        System.arraycopy(bArr3, 0, bArr12, 0, roundedPolynomialBytes);
        System.arraycopy(bArr4, 0, bArr12, roundedPolynomialBytes, 128);
        System.arraycopy(hashWithPrefix2, 0, bArr12, i, hashWithPrefix2.length / 2);
        Utils.updateDiffMask(bArr7, this.privateKey.getRho(), Arrays.areEqual(bArr, bArr12) ? 0 : -1);
        byte[] bArr13 = new byte[32 + length];
        System.arraycopy(bArr7, 0, bArr13, 0, 32);
        System.arraycopy(bArr12, 0, bArr13, 32, length);
        return Arrays.copyOfRange(Utils.getHashWithPrefix(new byte[]{1}, bArr13), 0, parameters.getSessionKeySize() / 8);
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretExtractor
    public int getEncapsulationLength() {
        return this.privateKey.getParameters().getRoundedPolynomialBytes() + CipherSuite.TLS_DH_RSA_WITH_AES_128_GCM_SHA256;
    }
}