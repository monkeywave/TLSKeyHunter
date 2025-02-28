package org.bouncycastle.crypto.p004ec;

import java.math.BigInteger;
import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.math.p010ec.ECAlgorithms;
import org.bouncycastle.math.p010ec.ECMultiplier;
import org.bouncycastle.math.p010ec.ECPoint;
import org.bouncycastle.math.p010ec.FixedPointCombMultiplier;

/* renamed from: org.bouncycastle.crypto.ec.ECNewPublicKeyTransform */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECNewPublicKeyTransform.class */
public class ECNewPublicKeyTransform implements ECPairTransform {
    private ECPublicKeyParameters key;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.p004ec.ECPairTransform
    public void init(CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ParametersWithRandom)) {
            if (!(cipherParameters instanceof ECPublicKeyParameters)) {
                throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
            }
            this.key = (ECPublicKeyParameters) cipherParameters;
            this.random = CryptoServicesRegistrar.getSecureRandom();
            return;
        }
        ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
        if (!(parametersWithRandom.getParameters() instanceof ECPublicKeyParameters)) {
            throw new IllegalArgumentException("ECPublicKeyParameters are required for new public key transform.");
        }
        this.key = (ECPublicKeyParameters) parametersWithRandom.getParameters();
        this.random = parametersWithRandom.getRandom();
    }

    @Override // org.bouncycastle.crypto.p004ec.ECPairTransform
    public ECPair transform(ECPair eCPair) {
        if (this.key == null) {
            throw new IllegalStateException("ECNewPublicKeyTransform not initialised");
        }
        ECDomainParameters parameters = this.key.getParameters();
        BigInteger n = parameters.getN();
        ECMultiplier createBasePointMultiplier = createBasePointMultiplier();
        BigInteger generateK = ECUtil.generateK(n, this.random);
        ECPoint[] eCPointArr = {createBasePointMultiplier.multiply(parameters.getG(), generateK), this.key.getQ().multiply(generateK).add(ECAlgorithms.cleanPoint(parameters.getCurve(), eCPair.getY()))};
        parameters.getCurve().normalizeAll(eCPointArr);
        return new ECPair(eCPointArr[0], eCPointArr[1]);
    }

    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}