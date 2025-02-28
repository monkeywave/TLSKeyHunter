package org.bouncycastle.pqc.crypto.xwing;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMPublicKeyParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class XWingPublicKeyParameters extends XWingKeyParameters {
    private final MLKEMPublicKeyParameters kybPub;
    private final X25519PublicKeyParameters xdhPub;

    /* JADX INFO: Access modifiers changed from: package-private */
    public XWingPublicKeyParameters(AsymmetricKeyParameter asymmetricKeyParameter, AsymmetricKeyParameter asymmetricKeyParameter2) {
        super(false);
        this.kybPub = (MLKEMPublicKeyParameters) asymmetricKeyParameter;
        this.xdhPub = (X25519PublicKeyParameters) asymmetricKeyParameter2;
    }

    public XWingPublicKeyParameters(byte[] bArr) {
        super(false);
        this.kybPub = new MLKEMPublicKeyParameters(MLKEMParameters.ml_kem_768, Arrays.copyOfRange(bArr, 0, bArr.length - 32));
        this.xdhPub = new X25519PublicKeyParameters(bArr, bArr.length - 32);
    }

    public byte[] getEncoded() {
        return Arrays.concatenate(this.kybPub.getEncoded(), this.xdhPub.getEncoded());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public MLKEMPublicKeyParameters getKyberPublicKey() {
        return this.kybPub;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public X25519PublicKeyParameters getXDHPublicKey() {
        return this.xdhPub;
    }
}