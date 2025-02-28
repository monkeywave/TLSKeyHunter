package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.RawAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.X448PrivateKeyParameters;

/* loaded from: classes2.dex */
public class XDHBasicAgreement implements BasicAgreement {
    private RawAgreement agreement;
    private int fieldSize = 0;
    private AsymmetricKeyParameter key;

    @Override // org.bouncycastle.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters cipherParameters) {
        byte[] bArr = new byte[this.fieldSize];
        this.agreement.calculateAgreement(cipherParameters, bArr, 0);
        return new BigInteger(1, bArr);
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public int getFieldSize() {
        return this.fieldSize;
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public void init(CipherParameters cipherParameters) {
        RawAgreement x448Agreement;
        if (cipherParameters instanceof X25519PrivateKeyParameters) {
            this.fieldSize = 32;
            x448Agreement = new X25519Agreement();
        } else if (!(cipherParameters instanceof X448PrivateKeyParameters)) {
            throw new IllegalArgumentException("key is neither X25519 nor X448");
        } else {
            this.fieldSize = 56;
            x448Agreement = new X448Agreement();
        }
        this.agreement = x448Agreement;
        this.key = (AsymmetricKeyParameter) cipherParameters;
        this.agreement.init(cipherParameters);
    }
}