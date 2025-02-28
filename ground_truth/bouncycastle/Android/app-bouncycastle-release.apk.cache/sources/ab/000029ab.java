package org.bouncycastle.pqc.crypto.gemss;

import java.security.SecureRandom;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/* loaded from: classes2.dex */
public class GeMSSSigner implements MessageSigner {
    private GeMSSPrivateKeyParameters privKey;
    private GeMSSPublicKeyParameters pubKey;
    private SecureRandom random;

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        GeMSSEngine engine = this.privKey.getParameters().getEngine();
        int i = ((engine.HFEnv + ((engine.NB_ITE - 1) * (engine.HFEnv - engine.HFEm))) + 7) >>> 3;
        byte[] bArr2 = new byte[bArr.length + i];
        System.arraycopy(bArr, 0, bArr2, i, bArr.length);
        engine.signHFE_FeistelPatarin(this.random, bArr2, bArr, 0, bArr.length, this.privKey.f1271sk);
        return bArr2;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        SecureRandom secureRandom;
        if (!z) {
            this.pubKey = (GeMSSPublicKeyParameters) cipherParameters;
            return;
        }
        if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            this.privKey = (GeMSSPrivateKeyParameters) parametersWithRandom.getParameters();
            secureRandom = parametersWithRandom.getRandom();
        } else {
            this.privKey = (GeMSSPrivateKeyParameters) cipherParameters;
            secureRandom = CryptoServicesRegistrar.getSecureRandom();
        }
        this.random = secureRandom;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        return this.pubKey.getParameters().getEngine().crypto_sign_open(this.pubKey.getPK(), bArr, bArr2) != 0;
    }
}