package org.bouncycastle.pqc.crypto.falcon;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.pqc.crypto.MessageSigner;

/* loaded from: classes2.dex */
public class FalconSigner implements MessageSigner {
    private byte[] encodedkey;
    private FalconNIST nist;

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public byte[] generateSignature(byte[] bArr) {
        return this.nist.crypto_sign(false, new byte[this.nist.CRYPTO_BYTES], bArr, 0, bArr.length, this.encodedkey, 0);
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public void init(boolean z, CipherParameters cipherParameters) {
        FalconNIST falconNIST;
        if (!z) {
            FalconPublicKeyParameters falconPublicKeyParameters = (FalconPublicKeyParameters) cipherParameters;
            this.encodedkey = falconPublicKeyParameters.getH();
            falconNIST = new FalconNIST(falconPublicKeyParameters.getParameters().getLogN(), falconPublicKeyParameters.getParameters().getNonceLength(), CryptoServicesRegistrar.getSecureRandom());
        } else if (cipherParameters instanceof ParametersWithRandom) {
            ParametersWithRandom parametersWithRandom = (ParametersWithRandom) cipherParameters;
            FalconPrivateKeyParameters falconPrivateKeyParameters = (FalconPrivateKeyParameters) parametersWithRandom.getParameters();
            this.encodedkey = falconPrivateKeyParameters.getEncoded();
            this.nist = new FalconNIST(falconPrivateKeyParameters.getParameters().getLogN(), falconPrivateKeyParameters.getParameters().getNonceLength(), parametersWithRandom.getRandom());
            return;
        } else {
            FalconPrivateKeyParameters falconPrivateKeyParameters2 = (FalconPrivateKeyParameters) cipherParameters;
            this.encodedkey = falconPrivateKeyParameters2.getEncoded();
            falconNIST = new FalconNIST(falconPrivateKeyParameters2.getParameters().getLogN(), falconPrivateKeyParameters2.getParameters().getNonceLength(), CryptoServicesRegistrar.getSecureRandom());
        }
        this.nist = falconNIST;
    }

    @Override // org.bouncycastle.pqc.crypto.MessageSigner
    public boolean verifySignature(byte[] bArr, byte[] bArr2) {
        if (bArr2[0] != ((byte) (this.nist.LOGN + 48))) {
            return false;
        }
        byte[] bArr3 = new byte[this.nist.NONCELEN];
        byte[] bArr4 = new byte[(bArr2.length - this.nist.NONCELEN) - 1];
        System.arraycopy(bArr2, 1, bArr3, 0, this.nist.NONCELEN);
        System.arraycopy(bArr2, this.nist.NONCELEN + 1, bArr4, 0, (bArr2.length - this.nist.NONCELEN) - 1);
        return this.nist.crypto_sign_open(false, bArr4, bArr3, bArr, this.encodedkey, 0) == 0;
    }
}