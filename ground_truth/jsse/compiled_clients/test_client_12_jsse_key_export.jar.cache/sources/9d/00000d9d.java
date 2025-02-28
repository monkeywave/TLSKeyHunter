package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/qtesla/QTESLAPublicKeyParameters.class */
public final class QTESLAPublicKeyParameters extends AsymmetricKeyParameter {
    private int securityCategory;
    private byte[] publicKey;

    public QTESLAPublicKeyParameters(int i, byte[] bArr) {
        super(false);
        if (bArr.length != QTESLASecurityCategory.getPublicSize(i)) {
            throw new IllegalArgumentException("invalid key size for security category");
        }
        this.securityCategory = i;
        this.publicKey = Arrays.clone(bArr);
    }

    public int getSecurityCategory() {
        return this.securityCategory;
    }

    public byte[] getPublicData() {
        return Arrays.clone(this.publicKey);
    }
}