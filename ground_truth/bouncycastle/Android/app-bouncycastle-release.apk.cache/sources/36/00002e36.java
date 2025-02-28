package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/* loaded from: classes2.dex */
public class JcaDefaultTlsCredentialedSigner extends DefaultTlsCredentialedSigner {
    public JcaDefaultTlsCredentialedSigner(TlsCryptoParameters tlsCryptoParameters, JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        super(tlsCryptoParameters, makeSigner(jcaTlsCrypto, privateKey, certificate, signatureAndHashAlgorithm), certificate, signatureAndHashAlgorithm);
    }

    private static TlsSigner makeSigner(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        String algorithm = privateKey.getAlgorithm();
        if ((privateKey instanceof RSAPrivateKey) || "RSA".equalsIgnoreCase(algorithm) || "RSASSA-PSS".equalsIgnoreCase(algorithm)) {
            if (signatureAndHashAlgorithm != null) {
                int from = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(from)) {
                    return new JcaTlsRSAPSSSigner(jcaTlsCrypto, privateKey, from);
                }
            }
            return new JcaTlsRSASigner(jcaTlsCrypto, privateKey);
        } else if ((privateKey instanceof DSAPrivateKey) || "DSA".equalsIgnoreCase(algorithm)) {
            return new JcaTlsDSASigner(jcaTlsCrypto, privateKey);
        } else {
            if (ECUtil.isECPrivateKey(privateKey)) {
                if (signatureAndHashAlgorithm != null) {
                    int from2 = SignatureScheme.from(signatureAndHashAlgorithm);
                    if (SignatureScheme.isECDSA(from2)) {
                        return new JcaTlsECDSA13Signer(jcaTlsCrypto, privateKey, from2);
                    }
                }
                return new JcaTlsECDSASigner(jcaTlsCrypto, privateKey);
            } else if (EdDSAParameterSpec.Ed25519.equalsIgnoreCase(algorithm)) {
                return new JcaTlsEd25519Signer(jcaTlsCrypto, privateKey);
            } else {
                if (EdDSAParameterSpec.Ed448.equalsIgnoreCase(algorithm)) {
                    return new JcaTlsEd448Signer(jcaTlsCrypto, privateKey);
                }
                throw new IllegalArgumentException("'privateKey' type not supported: " + privateKey.getClass().getName());
            }
        }
    }
}