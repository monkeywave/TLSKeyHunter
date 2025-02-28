package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/DSTU4145KeyPairGenerator.class */
public class DSTU4145KeyPairGenerator extends ECKeyPairGenerator {
    @Override // org.bouncycastle.crypto.generators.ECKeyPairGenerator, org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        AsymmetricCipherKeyPair generateKeyPair = super.generateKeyPair();
        ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters) generateKeyPair.getPublic();
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new ECPublicKeyParameters(eCPublicKeyParameters.getQ().negate(), eCPublicKeyParameters.getParameters()), (AsymmetricKeyParameter) ((ECPrivateKeyParameters) generateKeyPair.getPrivate()));
    }
}