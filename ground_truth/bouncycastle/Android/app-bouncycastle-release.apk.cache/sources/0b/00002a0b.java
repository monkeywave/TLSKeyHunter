package org.bouncycastle.pqc.crypto.mlkem;

import java.security.SecureRandom;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;

/* loaded from: classes2.dex */
public class MLKEMGenerator implements EncapsulatedSecretGenerator {

    /* renamed from: sr */
    private final SecureRandom f1349sr;

    public MLKEMGenerator(SecureRandom secureRandom) {
        this.f1349sr = secureRandom;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter) {
        MLKEMPublicKeyParameters mLKEMPublicKeyParameters = (MLKEMPublicKeyParameters) asymmetricKeyParameter;
        MLKEMEngine engine = mLKEMPublicKeyParameters.getParameters().getEngine();
        engine.init(this.f1349sr);
        byte[] bArr = new byte[32];
        engine.getRandomBytes(bArr);
        byte[][] kemEncrypt = engine.kemEncrypt(mLKEMPublicKeyParameters.getEncoded(), bArr);
        return new SecretWithEncapsulationImpl(kemEncrypt[0], kemEncrypt[1]);
    }

    public SecretWithEncapsulation internalGenerateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter, byte[] bArr) {
        MLKEMPublicKeyParameters mLKEMPublicKeyParameters = (MLKEMPublicKeyParameters) asymmetricKeyParameter;
        MLKEMEngine engine = mLKEMPublicKeyParameters.getParameters().getEngine();
        engine.init(this.f1349sr);
        byte[][] kemEncryptInternal = engine.kemEncryptInternal(mLKEMPublicKeyParameters.getEncoded(), bArr);
        return new SecretWithEncapsulationImpl(kemEncryptInternal[0], kemEncryptInternal[1]);
    }
}