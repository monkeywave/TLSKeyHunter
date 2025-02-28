package org.bouncycastle.pqc.crypto.qtesla;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/crypto/qtesla/QTESLAKeyPairGenerator.class */
public final class QTESLAKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private int securityCategory;
    private SecureRandom secureRandom;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        QTESLAKeyGenerationParameters qTESLAKeyGenerationParameters = (QTESLAKeyGenerationParameters) keyGenerationParameters;
        this.secureRandom = qTESLAKeyGenerationParameters.getRandom();
        this.securityCategory = qTESLAKeyGenerationParameters.getSecurityCategory();
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        byte[] allocatePrivate = allocatePrivate(this.securityCategory);
        byte[] allocatePublic = allocatePublic(this.securityCategory);
        switch (this.securityCategory) {
            case 5:
                QTesla1p.generateKeyPair(allocatePublic, allocatePrivate, this.secureRandom);
                break;
            case 6:
                QTesla3p.generateKeyPair(allocatePublic, allocatePrivate, this.secureRandom);
                break;
            default:
                throw new IllegalArgumentException("unknown security category: " + this.securityCategory);
        }
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new QTESLAPublicKeyParameters(this.securityCategory, allocatePublic), (AsymmetricKeyParameter) new QTESLAPrivateKeyParameters(this.securityCategory, allocatePrivate));
    }

    private byte[] allocatePrivate(int i) {
        return new byte[QTESLASecurityCategory.getPrivateSize(i)];
    }

    private byte[] allocatePublic(int i) {
        return new byte[QTESLASecurityCategory.getPublicSize(i)];
    }
}