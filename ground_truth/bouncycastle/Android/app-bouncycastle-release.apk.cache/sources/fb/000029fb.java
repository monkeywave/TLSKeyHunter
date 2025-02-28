package org.bouncycastle.pqc.crypto.mldsa;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class MLDSAPrivateKeyParameters extends MLDSAKeyParameters {

    /* renamed from: k */
    final byte[] f1342k;
    final byte[] rho;

    /* renamed from: s1 */
    final byte[] f1343s1;

    /* renamed from: s2 */
    final byte[] f1344s2;
    private final byte[] seed;

    /* renamed from: t0 */
    final byte[] f1345t0;

    /* renamed from: t1 */
    private final byte[] f1346t1;

    /* renamed from: tr */
    final byte[] f1347tr;

    public MLDSAPrivateKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr) {
        super(true, mLDSAParameters);
        byte[][] generateKeyPairInternal = mLDSAParameters.getEngine(null).generateKeyPairInternal(bArr);
        this.rho = generateKeyPairInternal[0];
        this.f1342k = generateKeyPairInternal[1];
        this.f1347tr = generateKeyPairInternal[2];
        this.f1343s1 = generateKeyPairInternal[3];
        this.f1344s2 = generateKeyPairInternal[4];
        this.f1345t0 = generateKeyPairInternal[5];
        this.f1346t1 = generateKeyPairInternal[6];
        this.seed = generateKeyPairInternal[7];
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr, MLDSAPublicKeyParameters mLDSAPublicKeyParameters) {
        super(true, mLDSAParameters);
        MLDSAEngine engine = mLDSAParameters.getEngine(null);
        this.rho = Arrays.copyOfRange(bArr, 0, 32);
        this.f1342k = Arrays.copyOfRange(bArr, 32, 64);
        this.f1347tr = Arrays.copyOfRange(bArr, 64, 128);
        int dilithiumL = (engine.getDilithiumL() * engine.getDilithiumPolyEtaPackedBytes()) + 128;
        this.f1343s1 = Arrays.copyOfRange(bArr, 128, dilithiumL);
        int dilithiumK = (engine.getDilithiumK() * engine.getDilithiumPolyEtaPackedBytes()) + dilithiumL;
        this.f1344s2 = Arrays.copyOfRange(bArr, dilithiumL, dilithiumK);
        this.f1345t0 = Arrays.copyOfRange(bArr, dilithiumK, (engine.getDilithiumK() * 416) + dilithiumK);
        if (mLDSAPublicKeyParameters != null) {
            this.f1346t1 = mLDSAPublicKeyParameters.getT1();
        } else {
            this.f1346t1 = null;
        }
        this.seed = null;
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6, byte[] bArr7) {
        this(mLDSAParameters, bArr, bArr2, bArr3, bArr4, bArr5, bArr6, bArr7, null);
    }

    public MLDSAPrivateKeyParameters(MLDSAParameters mLDSAParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6, byte[] bArr7, byte[] bArr8) {
        super(true, mLDSAParameters);
        this.rho = Arrays.clone(bArr);
        this.f1342k = Arrays.clone(bArr2);
        this.f1347tr = Arrays.clone(bArr3);
        this.f1343s1 = Arrays.clone(bArr4);
        this.f1344s2 = Arrays.clone(bArr5);
        this.f1345t0 = Arrays.clone(bArr6);
        this.f1346t1 = Arrays.clone(bArr7);
        this.seed = Arrays.clone(bArr8);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(new byte[][]{this.rho, this.f1342k, this.f1347tr, this.f1343s1, this.f1344s2, this.f1345t0});
    }

    public byte[] getK() {
        return Arrays.clone(this.f1342k);
    }

    public byte[] getPrivateKey() {
        return getEncoded();
    }

    public byte[] getPublicKey() {
        return MLDSAPublicKeyParameters.getEncoded(this.rho, this.f1346t1);
    }

    public MLDSAPublicKeyParameters getPublicKeyParameters() {
        return new MLDSAPublicKeyParameters(getParameters(), this.rho, this.f1346t1);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getS1() {
        return Arrays.clone(this.f1343s1);
    }

    public byte[] getS2() {
        return Arrays.clone(this.f1344s2);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public byte[] getT0() {
        return Arrays.clone(this.f1345t0);
    }

    public byte[] getT1() {
        return Arrays.clone(this.f1346t1);
    }

    public byte[] getTr() {
        return Arrays.clone(this.f1347tr);
    }
}