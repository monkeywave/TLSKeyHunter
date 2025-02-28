package org.bouncycastle.pqc.crypto.crystals.dilithium;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/* loaded from: classes2.dex */
public class DilithiumSigner implements MessageSigner {
    private DilithiumPrivateKeyParameters privKey;
    private DilithiumPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        return this.privKey.getParameters().getEngine(this.random).sign(bArr, bArr.length, this.privKey.rho, this.privKey.f1223k, this.privKey.f1228tr, this.privKey.f1226t0, this.privKey.f1224s1, this.privKey.f1225s2);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        SecureRandom secureRandom;
        if (!z) {
            this.pubKey = (DilithiumPublicKeyParameters) cipherParameters;
            return;
        }
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.privKey = (DilithiumPrivateKeyParameters) parametersWithRandom.getParameters();
            secureRandom = parametersWithRandom.getRandom();
        } else {
            this.privKey = (DilithiumPrivateKeyParameters) cipherParameters;
            secureRandom = null;
        }
        this.random = secureRandom;
    }

    public byte[] internalGenerateSignature(byte[] bArr, byte[] bArr2) {
        return this.privKey.getParameters().getEngine(this.random).signSignatureInternal(bArr, bArr.length, this.privKey.rho, this.privKey.f1223k, this.privKey.f1228tr, this.privKey.f1226t0, this.privKey.f1224s1, this.privKey.f1225s2, bArr2);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        return this.pubKey.getParameters().getEngine(this.random).signOpen(bArr, bArr2, bArr2.length, this.pubKey.rho, this.pubKey.f1229t1);
    }
}