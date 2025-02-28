package org.bouncycastle.pqc.crypto.ntru;

import java.security.SecureRandom;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;

/* loaded from: classes2.dex */
public class NTRUKeyPairGenerator implements AsymmetricCipherKeyPairGenerator {
    private NTRUKeyGenerationParameters params;
    private SecureRandom random;

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public AsymmetricCipherKeyPair generateKeyPair() {
        NTRUParameterSet nTRUParameterSet = this.params.getParameters().parameterSet;
        byte[] bArr = new byte[nTRUParameterSet.sampleFgBytes()];
        this.random.nextBytes(bArr);
        OWCPAKeyPair keypair = new NTRUOWCPA(nTRUParameterSet).keypair(bArr);
        byte[] bArr2 = keypair.publicKey;
        byte[] bArr3 = new byte[nTRUParameterSet.ntruSecretKeyBytes()];
        byte[] bArr4 = keypair.privateKey;
        System.arraycopy(bArr4, 0, bArr3, 0, bArr4.length);
        int prfKeyBytes = nTRUParameterSet.prfKeyBytes();
        byte[] bArr5 = new byte[prfKeyBytes];
        this.random.nextBytes(bArr5);
        System.arraycopy(bArr5, 0, bArr3, nTRUParameterSet.owcpaSecretKeyBytes(), prfKeyBytes);
        return new AsymmetricCipherKeyPair((AsymmetricKeyParameter) new NTRUPublicKeyParameters(this.params.getParameters(), bArr2), (AsymmetricKeyParameter) new NTRUPrivateKeyParameters(this.params.getParameters(), bArr3));
    }

    @Override // org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator
    public void init(KeyGenerationParameters keyGenerationParameters) {
        this.params = (NTRUKeyGenerationParameters) keyGenerationParameters;
        this.random = keyGenerationParameters.getRandom();
    }
}