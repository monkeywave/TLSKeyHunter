package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.BasicAgreement;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.DHMQVPrivateParameters;
import org.bouncycastle.crypto.params.DHMQVPublicParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

/* loaded from: classes2.dex */
public class MQVBasicAgreement implements BasicAgreement {
    private static final BigInteger ONE = BigInteger.valueOf(1);
    DHMQVPrivateParameters privParams;

    private BigInteger calculateDHMQVAgreement(DHParameters dHParameters, DHPrivateKeyParameters dHPrivateKeyParameters, DHPublicKeyParameters dHPublicKeyParameters, DHPrivateKeyParameters dHPrivateKeyParameters2, DHPublicKeyParameters dHPublicKeyParameters2, DHPublicKeyParameters dHPublicKeyParameters3) {
        BigInteger q = dHParameters.getQ();
        BigInteger pow = BigInteger.valueOf(2L).pow((q.bitLength() + 1) / 2);
        return dHPublicKeyParameters3.getY().multiply(dHPublicKeyParameters.getY().modPow(dHPublicKeyParameters3.getY().mod(pow).add(pow), dHParameters.getP())).modPow(dHPrivateKeyParameters2.getX().add(dHPublicKeyParameters2.getY().mod(pow).add(pow).multiply(dHPrivateKeyParameters.getX())).mod(q), dHParameters.getP());
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters cipherParameters) {
        DHMQVPublicParameters dHMQVPublicParameters = (DHMQVPublicParameters) cipherParameters;
        DHPrivateKeyParameters staticPrivateKey = this.privParams.getStaticPrivateKey();
        if (this.privParams.getStaticPrivateKey().getParameters().equals(dHMQVPublicParameters.getStaticPublicKey().getParameters())) {
            if (this.privParams.getStaticPrivateKey().getParameters().getQ() != null) {
                BigInteger calculateDHMQVAgreement = calculateDHMQVAgreement(staticPrivateKey.getParameters(), staticPrivateKey, dHMQVPublicParameters.getStaticPublicKey(), this.privParams.getEphemeralPrivateKey(), this.privParams.getEphemeralPublicKey(), dHMQVPublicParameters.getEphemeralPublicKey());
                if (calculateDHMQVAgreement.equals(ONE)) {
                    throw new IllegalStateException("1 is not a valid agreement value for MQV");
                }
                return calculateDHMQVAgreement;
            }
            throw new IllegalStateException("MQV key domain parameters do not have Q set");
        }
        throw new IllegalStateException("MQV public key components have wrong domain parameters");
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public int getFieldSize() {
        return (this.privParams.getStaticPrivateKey().getParameters().getP().bitLength() + 7) / 8;
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public void init(CipherParameters cipherParameters) {
        DHMQVPrivateParameters dHMQVPrivateParameters = (DHMQVPrivateParameters) cipherParameters;
        this.privParams = dHMQVPrivateParameters;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("MQV", dHMQVPrivateParameters.getStaticPrivateKey()));
    }
}