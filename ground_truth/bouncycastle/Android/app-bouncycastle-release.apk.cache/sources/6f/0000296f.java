package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class DilithiumPrivateKeyParameters extends DilithiumKeyParameters {

    /* renamed from: k */
    final byte[] f1223k;
    final byte[] rho;

    /* renamed from: s1 */
    final byte[] f1224s1;

    /* renamed from: s2 */
    final byte[] f1225s2;

    /* renamed from: t0 */
    final byte[] f1226t0;

    /* renamed from: t1 */
    private final byte[] f1227t1;

    /* renamed from: tr */
    final byte[] f1228tr;

    public DilithiumPrivateKeyParameters(DilithiumParameters dilithiumParameters, byte[] bArr, DilithiumPublicKeyParameters dilithiumPublicKeyParameters) {
        super(true, dilithiumParameters);
        DilithiumEngine engine = dilithiumParameters.getEngine(null);
        this.rho = Arrays.copyOfRange(bArr, 0, 32);
        this.f1223k = Arrays.copyOfRange(bArr, 32, 64);
        this.f1228tr = Arrays.copyOfRange(bArr, 64, 128);
        int dilithiumL = (engine.getDilithiumL() * engine.getDilithiumPolyEtaPackedBytes()) + 128;
        this.f1224s1 = Arrays.copyOfRange(bArr, 128, dilithiumL);
        int dilithiumK = (engine.getDilithiumK() * engine.getDilithiumPolyEtaPackedBytes()) + dilithiumL;
        this.f1225s2 = Arrays.copyOfRange(bArr, dilithiumL, dilithiumK);
        this.f1226t0 = Arrays.copyOfRange(bArr, dilithiumK, (engine.getDilithiumK() * 416) + dilithiumK);
        if (dilithiumPublicKeyParameters != null) {
            this.f1227t1 = dilithiumPublicKeyParameters.getT1();
        } else {
            this.f1227t1 = null;
        }
    }

    public DilithiumPrivateKeyParameters(DilithiumParameters dilithiumParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5, byte[] bArr6, byte[] bArr7) {
        super(true, dilithiumParameters);
        this.rho = Arrays.clone(bArr);
        this.f1223k = Arrays.clone(bArr2);
        this.f1228tr = Arrays.clone(bArr3);
        this.f1224s1 = Arrays.clone(bArr4);
        this.f1225s2 = Arrays.clone(bArr5);
        this.f1226t0 = Arrays.clone(bArr6);
        this.f1227t1 = Arrays.clone(bArr7);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(new byte[][]{this.rho, this.f1223k, this.f1228tr, this.f1224s1, this.f1225s2, this.f1226t0});
    }

    public byte[] getK() {
        return Arrays.clone(this.f1223k);
    }

    public byte[] getPrivateKey() {
        return getEncoded();
    }

    public byte[] getPublicKey() {
        return DilithiumPublicKeyParameters.getEncoded(this.rho, this.f1227t1);
    }

    public DilithiumPublicKeyParameters getPublicKeyParameters() {
        return new DilithiumPublicKeyParameters(getParameters(), this.rho, this.f1227t1);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getS1() {
        return Arrays.clone(this.f1224s1);
    }

    public byte[] getS2() {
        return Arrays.clone(this.f1225s2);
    }

    public byte[] getT0() {
        return Arrays.clone(this.f1226t0);
    }

    public byte[] getT1() {
        return Arrays.clone(this.f1227t1);
    }

    public byte[] getTr() {
        return Arrays.clone(this.f1228tr);
    }
}