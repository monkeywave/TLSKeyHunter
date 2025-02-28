package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.PrivateKey;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsSigner;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* loaded from: classes2.dex */
public class JcaTlsRSAPSSSigner implements TlsSigner {
    private final JcaTlsCrypto crypto;
    private final PrivateKey privateKey;
    private final int signatureScheme;

    public JcaTlsRSAPSSSigner(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey, int i) {
        if (jcaTlsCrypto == null) {
            throw new NullPointerException("crypto");
        }
        if (privateKey == null) {
            throw new NullPointerException("privateKey");
        }
        if (!SignatureScheme.isRSAPSS(i)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.crypto = jcaTlsCrypto;
        this.privateKey = privateKey;
        this.signatureScheme = i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException {
        if (signatureAndHashAlgorithm != null) {
            int from = SignatureScheme.from(signatureAndHashAlgorithm);
            int i = this.signatureScheme;
            if (from == i) {
                int cryptoHashAlgorithm = SignatureScheme.getCryptoHashAlgorithm(i);
                String digestName = this.crypto.getDigestName(cryptoHashAlgorithm);
                return this.crypto.createStreamSigner(RSAUtil.getDigestSigAlgName(digestName) + "WITHRSAANDMGF1", RSAUtil.getPSSParameterSpec(cryptoHashAlgorithm, digestName, this.crypto.getHelper()), this.privateKey, true);
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
    }
}