package org.bouncycastle.pqc.crypto.slhdsa;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SLHDSAPublicKeyParameters extends SLHDSAKeyParameters {

    /* renamed from: pk */
    private final C1400PK f1421pk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SLHDSAPublicKeyParameters(SLHDSAParameters sLHDSAParameters, C1400PK c1400pk) {
        super(false, sLHDSAParameters);
        this.f1421pk = c1400pk;
    }

    public SLHDSAPublicKeyParameters(SLHDSAParameters sLHDSAParameters, byte[] bArr) {
        super(false, sLHDSAParameters);
        int n = sLHDSAParameters.getN();
        int i = n * 2;
        if (bArr.length != i) {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.f1421pk = new C1400PK(Arrays.copyOfRange(bArr, 0, n), Arrays.copyOfRange(bArr, n, i));
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f1421pk.seed, this.f1421pk.root);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.f1421pk.root);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f1421pk.seed);
    }
}