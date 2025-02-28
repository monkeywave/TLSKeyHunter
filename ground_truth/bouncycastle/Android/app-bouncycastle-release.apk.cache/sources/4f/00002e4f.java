package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PublicKey;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;
import org.bouncycastle.tls.crypto.TlsVerifier;

/* loaded from: classes2.dex */
public class JcaTlsRSAPSSVerifier implements TlsVerifier {
    private final JcaTlsCrypto crypto;
    private final PublicKey publicKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSVerifier(JcaTlsCrypto jcaTlsCrypto, PublicKey publicKey, int i) {
        if (jcaTlsCrypto == null) {
            throw new NullPointerException("crypto");
        }
        if (publicKey == null) {
            throw new NullPointerException("publicKey");
        }
        if (!SignatureScheme.isRSAPSS(i)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.crypto = jcaTlsCrypto;
        this.publicKey = publicKey;
        this.signatureScheme = i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public TlsStreamVerifier getStreamVerifier(DigitallySigned digitallySigned) throws IOException {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm != null) {
            int from = SignatureScheme.from(algorithm);
            int i = this.signatureScheme;
            if (from == i) {
                int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i);
                String digestName = this.crypto.getDigestName(cryptoHashAlgorithm);
                return this.crypto.createStreamVerifier(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.crypto.getHelper()), digitallySigned.getSignature(), this.publicKey);
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) throws IOException {
        throw new UnsupportedOperationException();
    }
}