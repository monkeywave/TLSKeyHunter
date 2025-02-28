package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPrivateKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class XWingPrivateKeyParameters extends XWingKeyParameters {
    private final MLKEMPrivateKeyParameters kybPriv;
    private final X25519PrivateKeyParameters xdhPriv;

    /* JADX INFO: Access modifiers changed from: package-private */
    public XWingPrivateKeyParameters(AsymmetricKeyParameter asymmetricKeyParameter, AsymmetricKeyParameter asymmetricKeyParameter2) {
        super(true);
        this.kybPriv = (MLKEMPrivateKeyParameters) asymmetricKeyParameter;
        this.xdhPriv = (X25519PrivateKeyParameters) asymmetricKeyParameter2;
    }

    public XWingPrivateKeyParameters(byte[] bArr) {
        super(false);
        this.kybPriv = new MLKEMPrivateKeyParameters(MLKEMParameters.ml_kem_768, Arrays.copyOfRange(bArr, 0, bArr.length - 32));
        this.xdhPriv = new X25519PrivateKeyParameters(bArr, bArr.length - 32);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.kybPriv.getEncoded(), this.xdhPriv.getEncoded());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLKEMPrivateKeyParameters getKyberPrivateKey() {
        return this.kybPriv;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X25519PrivateKeyParameters getXDHPrivateKey() {
        return this.xdhPriv;
    }
}