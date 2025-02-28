package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.tls.TlsRsaKeyExchange;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.TlsCredentialedDecryptor;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSecret;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedDecryptor */
/* loaded from: classes2.dex */
public class BcDefaultTlsCredentialedDecryptor implements TlsCredentialedDecryptor {
    protected Certificate certificate;
    protected BcTlsCrypto crypto;
    protected AsymmetricKeyParameter privateKey;

    public BcDefaultTlsCredentialedDecryptor(BcTlsCrypto bcTlsCrypto, Certificate certificate, AsymmetricKeyParameter asymmetricKeyParameter) {
        if (bcTlsCrypto == null) {
            throw new IllegalArgumentException("'crypto' cannot be null");
        }
        if (certificate == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (asymmetricKeyParameter == null) {
            throw new IllegalArgumentException("'privateKey' cannot be null");
        }
        if (!asymmetricKeyParameter.isPrivate()) {
            throw new IllegalArgumentException("'privateKey' must be private");
        }
        if (!(asymmetricKeyParameter instanceof RSAKeyParameters)) {
            throw new IllegalArgumentException("'privateKey' type not supported: " + asymmetricKeyParameter.getClass().getName());
        }
        this.crypto = bcTlsCrypto;
        this.certificate = certificate;
        this.privateKey = asymmetricKeyParameter;
    }

    @Override // org.bouncycastle.tls.TlsCredentialedDecryptor
    public TlsSecret decrypt(TlsCryptoParameters tlsCryptoParameters, byte[] bArr) throws IOException {
        return safeDecryptPreMasterSecret(tlsCryptoParameters, (RSAKeyParameters) this.privateKey, bArr);
    }

    @Override // org.bouncycastle.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    protected TlsSecret safeDecryptPreMasterSecret(TlsCryptoParameters tlsCryptoParameters, RSAKeyParameters rSAKeyParameters, byte[] bArr) {
        return this.crypto.createSecret(TlsRsaKeyExchange.decryptPreMasterSecret(bArr, 0, bArr.length, rSAKeyParameters, tlsCryptoParameters.getRSAPreMasterSecretVersion().getFullVersion(), this.crypto.getSecureRandom()));
    }
}