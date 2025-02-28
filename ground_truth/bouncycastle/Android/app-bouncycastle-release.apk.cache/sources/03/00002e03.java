package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.tls.Certificate;
import org.bouncycastle.tls.DefaultTlsCredentialedSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.crypto.TlsCryptoParameters;
import org.bouncycastle.tls.crypto.TlsSigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcDefaultTlsCredentialedSigner */
/* loaded from: classes2.dex */
public class BcDefaultTlsCredentialedSigner extends DefaultTlsCredentialedSigner {
    public BcDefaultTlsCredentialedSigner(TlsCryptoParameters tlsCryptoParameters, BcTlsCrypto bcTlsCrypto, AsymmetricKeyParameter asymmetricKeyParameter, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        super(tlsCryptoParameters, makeSigner(bcTlsCrypto, asymmetricKeyParameter, certificate, signatureAndHashAlgorithm), certificate, signatureAndHashAlgorithm);
    }

    private static TlsSigner makeSigner(BcTlsCrypto bcTlsCrypto, AsymmetricKeyParameter asymmetricKeyParameter, Certificate certificate, SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (asymmetricKeyParameter instanceof RSAKeyParameters) {
            RSAKeyParameters rSAKeyParameters = (RSAKeyParameters) asymmetricKeyParameter;
            if (signatureAndHashAlgorithm != null) {
                int from = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isRSAPSS(from)) {
                    return new BcTlsRSAPSSSigner(bcTlsCrypto, rSAKeyParameters, from);
                }
            }
            return new BcTlsRSASigner(bcTlsCrypto, rSAKeyParameters);
        } else if (asymmetricKeyParameter instanceof DSAPrivateKeyParameters) {
            return new BcTlsDSASigner(bcTlsCrypto, (DSAPrivateKeyParameters) asymmetricKeyParameter);
        } else {
            if (!(asymmetricKeyParameter instanceof ECPrivateKeyParameters)) {
                if (asymmetricKeyParameter instanceof Ed25519PrivateKeyParameters) {
                    return new BcTlsEd25519Signer(bcTlsCrypto, (Ed25519PrivateKeyParameters) asymmetricKeyParameter);
                }
                if (asymmetricKeyParameter instanceof Ed448PrivateKeyParameters) {
                    return new BcTlsEd448Signer(bcTlsCrypto, (Ed448PrivateKeyParameters) asymmetricKeyParameter);
                }
                throw new IllegalArgumentException("'privateKey' type not supported: " + asymmetricKeyParameter.getClass().getName());
            }
            ECPrivateKeyParameters eCPrivateKeyParameters = (ECPrivateKeyParameters) asymmetricKeyParameter;
            if (signatureAndHashAlgorithm != null) {
                int from2 = SignatureScheme.from(signatureAndHashAlgorithm);
                if (SignatureScheme.isECDSA(from2)) {
                    return new BcTlsECDSA13Signer(bcTlsCrypto, eCPrivateKeyParameters, from2);
                }
            }
            return new BcTlsECDSASigner(bcTlsCrypto, eCPrivateKeyParameters);
        }
    }
}