package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class SPHINCSPlusPublicKeyParameters extends SPHINCSPlusKeyParameters {

    /* renamed from: pk */
    private final C1403PK f1453pk;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, C1403PK c1403pk) {
        super(false, sPHINCSPlusParameters);
        this.f1453pk = c1403pk;
    }

    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, byte[] bArr) {
        super(false, sPHINCSPlusParameters);
        int n = sPHINCSPlusParameters.getN();
        int i = n * 2;
        if (bArr.length != i) {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.f1453pk = new C1403PK(Arrays.copyOfRange(bArr, 0, n), Arrays.copyOfRange(bArr, n, i));
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f1453pk.seed, this.f1453pk.root);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.f1453pk.root);
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f1453pk.seed);
    }
}