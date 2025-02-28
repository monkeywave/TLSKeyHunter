package org.bouncycastle.pqc.crypto.mlkem;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class MLKEMPrivateKeyParameters extends MLKEMKeyParameters {
    final byte[] hpk;
    final byte[] nonce;
    final byte[] rho;

    /* renamed from: s */
    final byte[] f1351s;
    final byte[] seed;

    /* renamed from: t */
    final byte[] f1352t;

    public MLKEMPrivateKeyParameters(MLKEMParameters mLKEMParameters, byte[] bArr) {
        super(true, mLKEMParameters);
        MLKEMEngine engine = mLKEMParameters.getEngine();
        if (bArr.length == 64) {
            byte[][] generateKemKeyPairInternal = engine.generateKemKeyPairInternal(Arrays.copyOfRange(bArr, 0, 32), Arrays.copyOfRange(bArr, 32, bArr.length));
            this.f1351s = generateKemKeyPairInternal[2];
            this.hpk = generateKemKeyPairInternal[3];
            this.nonce = generateKemKeyPairInternal[4];
            this.f1352t = generateKemKeyPairInternal[0];
            this.rho = generateKemKeyPairInternal[1];
            this.seed = generateKemKeyPairInternal[5];
            return;
        }
        this.f1351s = Arrays.copyOfRange(bArr, 0, engine.getKyberIndCpaSecretKeyBytes());
        int kyberIndCpaSecretKeyBytes = engine.getKyberIndCpaSecretKeyBytes();
        this.f1352t = Arrays.copyOfRange(bArr, kyberIndCpaSecretKeyBytes, (engine.getKyberIndCpaPublicKeyBytes() + kyberIndCpaSecretKeyBytes) - 32);
        int kyberIndCpaPublicKeyBytes = kyberIndCpaSecretKeyBytes + (engine.getKyberIndCpaPublicKeyBytes() - 32);
        int i = kyberIndCpaPublicKeyBytes + 32;
        this.rho = Arrays.copyOfRange(bArr, kyberIndCpaPublicKeyBytes, i);
        int i2 = kyberIndCpaPublicKeyBytes + 64;
        this.hpk = Arrays.copyOfRange(bArr, i, i2);
        this.nonce = Arrays.copyOfRange(bArr, i2, kyberIndCpaPublicKeyBytes + 96);
        this.seed = null;
    }

    public MLKEMPrivateKeyParameters(MLKEMParameters mLKEMParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5) {
        this(mLKEMParameters, bArr, bArr2, bArr3, bArr4, bArr5, null);
    }

    public MLKEMPrivateKeyParameters(MLKEMParameters mLKEMParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6) {
        super(true, mLKEMParameters);
        this.f1351s = Arrays.clone(bArr);
        this.hpk = Arrays.clone(bArr2);
        this.nonce = Arrays.clone(bArr3);
        this.f1352t = Arrays.clone(bArr4);
        this.rho = Arrays.clone(bArr5);
        this.seed = Arrays.clone(bArr6);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(new byte[][]{this.f1351s, this.f1352t, this.rho, this.hpk, this.nonce});
    }

    public byte[] getHPK() {
        return Arrays.clone(this.hpk);
    }

    public byte[] getNonce() {
        return Arrays.clone(this.nonce);
    }

    public byte[] getPublicKey() {
        return MLKEMPublicKeyParameters.getEncoded(this.f1352t, this.rho);
    }

    public MLKEMPublicKeyParameters getPublicKeyParameters() {
        return new MLKEMPublicKeyParameters(getParameters(), this.f1352t, this.rho);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getS() {
        return Arrays.clone(this.f1351s);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public byte[] getT() {
        return Arrays.clone(this.f1352t);
    }
}