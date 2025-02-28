package org.bouncycastle.pqc.crypto.qtesla;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/qtesla/QTESLAPrivateKeyParameters.class */
public final class QTESLAPrivateKeyParameters extends AsymmetricKeyParameter {
    private int securityCategory;
    private byte[] privateKey;

    public QTESLAPrivateKeyParameters(int i, byte[] bArr) {
        super(true);
        if (bArr.length != QTESLASecurityCategory.getPrivateSize(i)) {
            throw new IllegalArgumentException("invalid key size for security category");
        }
        this.securityCategory = i;
        this.privateKey = Arrays.clone(bArr);
    }

    public int getSecurityCategory() {
        return this.securityCategory;
    }

    public byte[] getSecret() {
        return Arrays.clone(this.privateKey);
    }
}