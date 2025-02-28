package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusPublicKeyParameters.class */
public class SPHINCSPlusPublicKeyParameters extends SPHINCSPlusKeyParameters {

    /* renamed from: pk */
    private final C0330PK f920pk;

    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, byte[] bArr) {
        super(false, sPHINCSPlusParameters);
        int i = sPHINCSPlusParameters.getEngine().f912N;
        if (bArr.length != 2 * i) {
            throw new IllegalArgumentException("public key encoding does not match parameters");
        }
        this.f920pk = new C0330PK(Arrays.copyOfRange(bArr, 0, i), Arrays.copyOfRange(bArr, i, 2 * i));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SPHINCSPlusPublicKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, C0330PK c0330pk) {
        super(false, sPHINCSPlusParameters);
        this.f920pk = c0330pk;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f920pk.seed);
    }

    public byte[] getRoot() {
        return Arrays.clone(this.f920pk.root);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f920pk.seed, this.f920pk.root);
    }
}