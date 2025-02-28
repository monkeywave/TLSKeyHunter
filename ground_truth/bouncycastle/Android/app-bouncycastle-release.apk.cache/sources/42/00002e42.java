package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* loaded from: classes2.dex */
public class JcaTlsDSASigner extends JcaTlsDSSSigner {
    public JcaTlsDSASigner(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey) {
        super(jcaTlsCrypto, privateKey, (short) 2, "NoneWithDSA");
    }

    @Override // org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsDSSSigner, org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        if (signatureAndHashAlgorithm == null || this.algorithmType != signatureAndHashAlgorithm.getSignature() || HashAlgorithm.getOutputSize(signatureAndHashAlgorithm.getHash()) == 20) {
            return null;
        }
        return this.crypto.createStreamSigner(signatureAndHashAlgorithm, this.privateKey, true);
    }
}