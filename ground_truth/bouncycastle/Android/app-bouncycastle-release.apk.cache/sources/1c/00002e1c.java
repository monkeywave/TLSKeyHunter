package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsEncryptor;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsRSAEncryptor */
/* loaded from: classes2.dex */
final class BcTlsRSAEncryptor implements TlsEncryptor {
    private final BcTlsCrypto crypto;
    private final RSAKeyParameters pubKeyRSA;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsRSAEncryptor(BcTlsCrypto bcTlsCrypto, RSAKeyParameters rSAKeyParameters) {
        this.crypto = bcTlsCrypto;
        this.pubKeyRSA = checkPublicKey(rSAKeyParameters);
    }

    private static RSAKeyParameters checkPublicKey(RSAKeyParameters rSAKeyParameters) {
        if (rSAKeyParameters == null || rSAKeyParameters.isPrivate()) {
            throw new IllegalArgumentException("No public RSA key provided");
        }
        return rSAKeyParameters;
    }

    @Override // org.bouncycastle.tls.crypto.TlsEncryptor
    public byte[] encrypt(byte[] bArr, int i, int i2) throws IOException {
        try {
            PKCS1Encoding pKCS1Encoding = new PKCS1Encoding(new RSABlindedEngine());
            pKCS1Encoding.init(true, new ParametersWithRandom(this.pubKeyRSA, this.crypto.getSecureRandom()));
            return pKCS1Encoding.processBlock(bArr, i, i2);
        } catch (InvalidCipherTextException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}