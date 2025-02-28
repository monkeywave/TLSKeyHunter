package org.bouncycastle.pqc.crypto.xwing;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.agreement.X25519Agreement;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.generators.X25519KeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.X25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.X25519PublicKeyParameters;
import org.bouncycastle.pqc.crypto.mlkem.MLKEMGenerator;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class XWingKEMGenerator implements EncapsulatedSecretGenerator {

    /* renamed from: sr */
    private final SecureRandom f1457sr;

    public XWingKEMGenerator(SecureRandom secureRandom) {
        this.f1457sr = secureRandom;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter) {
        XWingPublicKeyParameters xWingPublicKeyParameters = (XWingPublicKeyParameters) asymmetricKeyParameter;
        SecretWithEncapsulation generateEncapsulated = new MLKEMGenerator(this.f1457sr).generateEncapsulated(xWingPublicKeyParameters.getKyberPublicKey());
        X25519Agreement x25519Agreement = new X25519Agreement();
        byte[] secret = generateEncapsulated.getSecret();
        int length = secret.length + x25519Agreement.getAgreementSize();
        byte[] bArr = new byte[length];
        System.arraycopy(secret, 0, bArr, 0, secret.length);
        Arrays.clear(secret);
        X25519KeyPairGenerator x25519KeyPairGenerator = new X25519KeyPairGenerator();
        x25519KeyPairGenerator.init(new X25519KeyGenerationParameters(this.f1457sr));
        AsymmetricCipherKeyPair generateKeyPair = x25519KeyPairGenerator.generateKeyPair();
        x25519Agreement.init(generateKeyPair.getPrivate());
        x25519Agreement.calculateAgreement(xWingPublicKeyParameters.getXDHPublicKey(), bArr, secret.length);
        X25519PublicKeyParameters x25519PublicKeyParameters = (X25519PublicKeyParameters) generateKeyPair.getPublic();
        SHA3Digest sHA3Digest = new SHA3Digest(256);
        sHA3Digest.update(Strings.toByteArray("\\.//^\\"), 0, 6);
        sHA3Digest.update(bArr, 0, length);
        sHA3Digest.update(x25519PublicKeyParameters.getEncoded(), 0, 32);
        sHA3Digest.update(xWingPublicKeyParameters.getXDHPublicKey().getEncoded(), 0, 32);
        byte[] bArr2 = new byte[32];
        sHA3Digest.doFinal(bArr2, 0);
        return new SecretWithEncapsulationImpl(bArr2, Arrays.concatenate(generateEncapsulated.getEncapsulation(), x25519PublicKeyParameters.getEncoded()));
    }
}