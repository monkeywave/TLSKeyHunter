package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/agreement/DHBasicAgreement.class */
public class DHBasicAgreement implements BasicAgreement {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    private DHPrivateKeyParameters key;
    private DHParameters dhParams;

    @Override // org.bouncycastle.crypto.BasicAgreement
    public void init(CipherParameters cipherParameters) {
        AsymmetricKeyParameter asymmetricKeyParameter = cipherParameters instanceof ParametersWithRandom ? (AsymmetricKeyParameter) ((ParametersWithRandom) cipherParameters).getParameters() : (AsymmetricKeyParameter) cipherParameters;
        if (!(asymmetricKeyParameter instanceof DHPrivateKeyParameters)) {
            throw new IllegalArgumentException("DHEngine expects DHPrivateKeyParameters");
        }
        this.key = (DHPrivateKeyParameters) asymmetricKeyParameter;
        this.dhParams = this.key.getParameters();
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.key.getParameters().getP().bitLength() + 7) / 8;
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters cipherParameters) {
        DHPublicKeyParameters dHPublicKeyParameters = (DHPublicKeyParameters) cipherParameters;
        if (dHPublicKeyParameters.getParameters().equals(this.dhParams)) {
            BigInteger p = this.dhParams.getP();
            BigInteger y = dHPublicKeyParameters.getY();
            if (y == null || y.compareTo(ONE) <= 0 || y.compareTo(p.subtract(ONE)) >= 0) {
                throw new IllegalArgumentException("Diffie-Hellman public key is weak");
            }
            BigInteger modPow = y.modPow(this.key.getX(), p);
            if (modPow.equals(ONE)) {
                throw new IllegalStateException("Shared key can't be 1");
            }
            return modPow;
        }
        throw new IllegalArgumentException("Diffie-Hellman public key has wrong parameters.");
    }
}