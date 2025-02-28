package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.GenericSigner;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsRSASigner */
/* loaded from: classes2.dex */
public class BcTlsRSASigner extends BcTlsSigner {
    public BcTlsRSASigner(BcTlsCrypto bcTlsCrypto, RSAKeyParameters rSAKeyParameters) {
        super(bcTlsCrypto, rSAKeyParameters);
    }

    public BcTlsRSASigner(BcTlsCrypto bcTlsCrypto, RSAKeyParameters rSAKeyParameters, RSAKeyParameters rSAKeyParameters2) {
        this(bcTlsCrypto, rSAKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        Signer genericSigner;
        NullDigest nullDigest = new NullDigest();
        if (signatureAndHashAlgorithm == null) {
            genericSigner = new GenericSigner(new PKCS1Encoding(new RSABlindedEngine()), nullDigest);
        } else if (signatureAndHashAlgorithm.getSignature() != 1) {
            throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
        } else {
            genericSigner = new RSADigestSigner(nullDigest, TlsUtils.getOIDForHashAlgorithm(signatureAndHashAlgorithm.getHash()));
        }
        genericSigner.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
        genericSigner.update(bArr, 0, bArr.length);
        try {
            return genericSigner.generateSignature();
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}