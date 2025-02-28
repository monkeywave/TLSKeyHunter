package org.bouncycastle.crypto.p004ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECElGamalDecryptor */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECElGamalDecryptor.class */
public class ECElGamalDecryptor implements ECDecryptor {
    private ECPrivateKeyParameters key;

    @Override // org.bouncycastle.crypto.p004ec.ECDecryptor
    public void init(CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ECPrivateKeyParameters)) {
            throw new IllegalArgumentException("ECPrivateKeyParameters are required for decryption.");
        }
        this.key = (ECPrivateKeyParameters) cipherParameters;
    }

    @Override // org.bouncycastle.crypto.p004ec.ECDecryptor
    public ECPoint decrypt(ECPair eCPair) {
        if (this.key == null) {
            throw new IllegalStateException("ECElGamalDecryptor not initialised");
        }
        ECCurve curve = this.key.getParameters().getCurve();
        return ECAlgorithms.cleanPoint(curve, eCPair.getY()).subtract(ECAlgorithms.cleanPoint(curve, eCPair.getX()).multiply(this.key.getD())).normalize();
    }
}