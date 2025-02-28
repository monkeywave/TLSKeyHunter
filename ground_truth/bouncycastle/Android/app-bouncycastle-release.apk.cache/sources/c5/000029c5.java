package org.bouncycastle.pqc.crypto.hqc;

import java.security.SecureRandom;
import org.bouncycastle.crypto.EncapsulatedSecretGenerator;
import org.bouncycastle.crypto.SecretWithEncapsulation;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.pqc.crypto.util.SecretWithEncapsulationImpl;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class HQCKEMGenerator implements EncapsulatedSecretGenerator {

    /* renamed from: sr */
    private final SecureRandom f1299sr;

    public HQCKEMGenerator(SecureRandom secureRandom) {
        this.f1299sr = secureRandom;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretGenerator
    public SecretWithEncapsulation generateEncapsulated(AsymmetricKeyParameter asymmetricKeyParameter) {
        HQCPublicKeyParameters hQCPublicKeyParameters = (HQCPublicKeyParameters) asymmetricKeyParameter;
        HQCEngine engine = hQCPublicKeyParameters.getParameters().getEngine();
        byte[] bArr = new byte[hQCPublicKeyParameters.getParameters().getSHA512_BYTES()];
        byte[] bArr2 = new byte[hQCPublicKeyParameters.getParameters().getN_BYTES()];
        byte[] bArr3 = new byte[hQCPublicKeyParameters.getParameters().getN1N2_BYTES()];
        byte[] bArr4 = new byte[hQCPublicKeyParameters.getParameters().getSHA512_BYTES()];
        byte[] bArr5 = new byte[hQCPublicKeyParameters.getParameters().getSALT_SIZE_BYTES()];
        byte[] publicKey = hQCPublicKeyParameters.getPublicKey();
        byte[] bArr6 = new byte[48];
        this.f1299sr.nextBytes(bArr6);
        engine.encaps(bArr2, bArr3, bArr, bArr4, publicKey, bArr6, bArr5);
        return new SecretWithEncapsulationImpl(Arrays.copyOfRange(bArr, 0, hQCPublicKeyParameters.getParameters().getK()), Arrays.concatenate(bArr2, bArr3, bArr4, bArr5));
    }
}