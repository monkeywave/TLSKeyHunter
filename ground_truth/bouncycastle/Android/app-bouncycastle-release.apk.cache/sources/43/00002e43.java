package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.HashAlgorithm;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

/* loaded from: classes2.dex */
public class JcaTlsDSAVerifier extends JcaTlsDSSVerifier {
    public JcaTlsDSAVerifier(JcaTlsCrypto jcaTlsCrypto, PublicKey publicKey) {
        super(jcaTlsCrypto, publicKey, (short) 2, "NoneWithDSA");
    }

    @Override // org.bouncycastle.tls.crypto.impl.jcajce.JcaTlsDSSVerifier, org.bouncycastle.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm == null || this.algorithmType != algorithm.getSignature() || HashAlgorithm.getOutputSize(algorithm.getHash()) == 20) {
            return null;
        }
        return this.crypto.createStreamVerifier(digitallySigned, this.publicKey);
    }
}