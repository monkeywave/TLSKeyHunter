package org.bouncycastle.crypto.agreement;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.StagedAgreement;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.p016ec.ECAlgorithms;
import org.bouncycastle.math.p016ec.ECPoint;

/* loaded from: classes2.dex */
public class ECDHCStagedAgreement implements StagedAgreement {
    ECPrivateKeyParameters key;

    private ECPoint calculateNextPoint(ECPublicKeyParameters eCPublicKeyParameters) {
        ECDomainParameters parameters = this.key.getParameters();
        if (parameters.equals(eCPublicKeyParameters.getParameters())) {
            BigInteger mod = parameters.getH().multiply(this.key.getD()).mod(parameters.getN());
            ECPoint cleanPoint = ECAlgorithms.cleanPoint(parameters.getCurve(), eCPublicKeyParameters.getQ());
            if (cleanPoint.isInfinity()) {
                throw new IllegalStateException("Infinity is not a valid public key for ECDHC");
            }
            ECPoint normalize = cleanPoint.multiply(mod).normalize();
            if (normalize.isInfinity()) {
                throw new IllegalStateException("Infinity is not a valid agreement value for ECDHC");
            }
            return normalize;
        }
        throw new IllegalStateException("ECDHC public key has wrong domain parameters");
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public BigInteger calculateAgreement(CipherParameters cipherParameters) {
        return calculateNextPoint((ECPublicKeyParameters) cipherParameters).getAffineXCoord().toBigInteger();
    }

    @Override // org.bouncycastle.crypto.StagedAgreement
    public AsymmetricKeyParameter calculateStage(CipherParameters cipherParameters) {
        return new ECPublicKeyParameters(calculateNextPoint((ECPublicKeyParameters) cipherParameters), this.key.getParameters());
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public int getFieldSize() {
        return this.key.getParameters().getCurve().getFieldElementEncodingLength();
    }

    @Override // org.bouncycastle.crypto.BasicAgreement
    public void init(CipherParameters cipherParameters) {
        ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters) cipherParameters;
        this.key = eCPrivateKeyParameters;
        CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties("ECCDH", eCPrivateKeyParameters));
    }
}