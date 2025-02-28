package org.bouncycastle.pqc.crypto.sphincsplus;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/sphincsplus/SPHINCSPlusPrivateKeyParameters.class */
public class SPHINCSPlusPrivateKeyParameters extends SPHINCSPlusKeyParameters {

    /* renamed from: sk */
    final C0331SK f918sk;

    /* renamed from: pk */
    final C0330PK f919pk;

    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, byte[] bArr) {
        super(true, sPHINCSPlusParameters);
        int i = sPHINCSPlusParameters.getEngine().f912N;
        if (bArr.length != 4 * i) {
            throw new IllegalArgumentException("private key encoding does not match parameters");
        }
        this.f918sk = new C0331SK(Arrays.copyOfRange(bArr, 0, i), Arrays.copyOfRange(bArr, i, 2 * i));
        this.f919pk = new C0330PK(Arrays.copyOfRange(bArr, 2 * i, 3 * i), Arrays.copyOfRange(bArr, 3 * i, 4 * i));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SPHINCSPlusPrivateKeyParameters(SPHINCSPlusParameters sPHINCSPlusParameters, C0331SK c0331sk, C0330PK c0330pk) {
        super(true, sPHINCSPlusParameters);
        this.f918sk = c0331sk;
        this.f919pk = c0330pk;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.f918sk.seed);
    }

    public byte[] getPrf() {
        return Arrays.clone(this.f918sk.prf);
    }

    public byte[] getPublicSeed() {
        return Arrays.clone(this.f919pk.seed);
    }

    public byte[] getPublicKey() {
        return Arrays.concatenate(this.f919pk.seed, this.f919pk.root);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.f918sk.seed, this.f918sk.prf, this.f919pk.seed, this.f919pk.root);
    }
}