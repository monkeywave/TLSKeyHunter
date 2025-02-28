package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SLHDSAPrivateKeyParameters extends SLHDSAKeyParameters {

    /* renamed from: pk */
    final C1400PK f1419pk;

    /* renamed from: sk */
    final C1401SK f1420sk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SLHDSAPrivateKeyParameters(SLHDSAParameters sLHDSAParameters, C1401SK c1401sk, C1400PK c1400pk) {
        super(true, sLHDSAParameters);
        this.f1420sk = c1401sk;
        this.f1419pk = c1400pk;
    }

    public SLHDSAPrivateKeyParameters(SLHDSAParameters sLHDSAParameters, byte[] bArr) {
        super(true, sLHDSAParameters);
        int n = sLHDSAParameters.getN();
        int i = n * 4;
        if (bArr.length != i) {
            throw new IllegalArgumentException("private key encoding does not match parameters");
        }
        int i2 = n * 2;
        this.f1420sk = new C1401SK(Arrays.copyOfRange(bArr, 0, n), Arrays.copyOfRange(bArr, n, i2));
        int i3 = n * 3;
        this.f1419pk = new C1400PK(Arrays.copyOfRange(bArr, i2, i3), Arrays.copyOfRange(bArr, i3, i));
    }

    public SLHDSAPrivateKeyParameters(SLHDSAParameters sLHDSAParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        super(true, sLHDSAParameters);
        this.f1420sk = new C1401SK(bArr, bArr2);
        this.f1419pk = new C1400PK(bArr3, bArr4);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(new byte[][]{this.f1420sk.seed, this.f1420sk.prf, this.f1419pk.seed, this.f1419pk.root});
    }

    public byte[] getEncodedPublicKey() {
        return Arrays.concatenate(this.f1419pk.seed, this.f1419pk.root);
    }

    public byte[] getPrf() {
        return Arrays.clone(this.f1420sk.prf);
    }

    public byte[] getPublicKey() {
        return Arrays.concatenate(this.f1419pk.seed, this.f1419pk.root);
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.f1419pk.seed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.f1419pk.root);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f1420sk.seed);
    }
}