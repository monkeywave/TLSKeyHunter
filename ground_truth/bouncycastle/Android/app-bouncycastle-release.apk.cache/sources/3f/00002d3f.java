package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.tls.crypto.impl.TlsImplUtils;

/* loaded from: classes2.dex */
public class DefaultTlsCredentialedSigner implements TlsCredentialedSigner {
    protected Certificate certificate;
    protected TlsCryptoParameters cryptoParams;
    protected SignatureAndHashAlgorithm signatureAndHashAlgorithm;
    protected TlsSigner signer;

    public DefaultTlsCredentialedSigner(TlsCryptoParameters tlsCryptoParameters, TlsSigner tlsSigner, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (certificate == null) {
            throw new IllegalArgumentException("'certificate' cannot be null");
        }
        if (certificate.isEmpty()) {
            throw new IllegalArgumentException("'certificate' cannot be empty");
        }
        if (tlsSigner == null) {
            throw new IllegalArgumentException("'signer' cannot be null");
        }
        this.signer = tlsSigner;
        this.cryptoParams = tlsCryptoParameters;
        this.certificate = certificate;
        this.signatureAndHashAlgorithm = signatureAndHashAlgorithm;
    }

    @Override // org.bouncycastle.tls.TlsCredentialedSigner
    public byte[] generateRawSignature(byte[] bArr) throws IOException {
        return this.signer.generateRawSignature(getEffectiveAlgorithm(), bArr);
    }

    @Override // org.bouncycastle.tls.TlsCredentials
    public Certificate getCertificate() {
        return this.certificate;
    }

    protected SignatureAndHashAlgorithm getEffectiveAlgorithm() {
        if (TlsImplUtils.isTLSv12(this.cryptoParams)) {
            SignatureAndHashAlgorithm signatureAndHashAlgorithm = getSignatureAndHashAlgorithm();
            if (signatureAndHashAlgorithm != null) {
                return signatureAndHashAlgorithm;
            }
            throw new IllegalStateException("'signatureAndHashAlgorithm' cannot be null for (D)TLS 1.2+");
        }
        return null;
    }

    @Override // org.bouncycastle.tls.TlsCredentialedSigner
    public SignatureAndHashAlgorithm getSignatureAndHashAlgorithm() {
        return this.signatureAndHashAlgorithm;
    }

    @Override // org.bouncycastle.tls.TlsCredentialedSigner
    public TlsStreamSigner getStreamSigner() throws IOException {
        return this.signer.getStreamSigner(getEffectiveAlgorithm());
    }
}