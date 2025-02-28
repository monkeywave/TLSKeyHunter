package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SPHINCSPlusPrivateKeyParameters extends SPHINCSPlusKeyParameters {

    /* renamed from: pk */
    final C1403PK f1451pk;

    /* renamed from: sk */
    final C1404SK f1452sk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, C1404SK c1404sk, C1403PK c1403pk) {
        super(true, sPHINCSPlusParameters);
        this.f1452sk = c1404sk;
        this.f1451pk = c1403pk;
    }

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, byte[] bArr) {
        super(true, sPHINCSPlusParameters);
        int n = sPHINCSPlusParameters.getN();
        int i = n * 4;
        if (bArr.length != i) {
            throw new IllegalArgumentException("private key encoding does not match parameters");
        }
        int i2 = n * 2;
        this.f1452sk = new C1404SK(Arrays.copyOfRange(bArr, 0, n), Arrays.copyOfRange(bArr, n, i2));
        int i3 = n * 3;
        this.f1451pk = new C1403PK(Arrays.copyOfRange(bArr, i2, i3), Arrays.copyOfRange(bArr, i3, i));
    }

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4) {
        super(true, sPHINCSPlusParameters);
        this.f1452sk = new C1404SK(bArr, bArr2);
        this.f1451pk = new C1403PK(bArr3, bArr4);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(new byte[][]{this.f1452sk.seed, this.f1452sk.prf, this.f1451pk.seed, this.f1451pk.root});
    }

    public byte[] getEncodedPublicKey() {
        return Arrays.concatenate(this.f1451pk.seed, this.f1451pk.root);
    }

    public byte[] getPrf() {
        return Arrays.clone(this.f1452sk.prf);
    }

    public byte[] getPublicKey() {
        return Arrays.concatenate(this.f1451pk.seed, this.f1451pk.root);
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.f1451pk.seed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.f1451pk.root);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f1452sk.seed);
    }
}