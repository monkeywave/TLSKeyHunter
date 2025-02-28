package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.digests.NullDigest;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.DSADigestSigner;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsECDSA13Signer */
/* loaded from: classes2.dex */
public class BcTlsECDSA13Signer extends BcTlsSigner {
    private final int signatureScheme;

    public BcTlsECDSA13Signer(BcTlsCrypto bcTlsCrypto, ECPrivateKeyParameters eCPrivateKeyParameters, int i) {
        super(bcTlsCrypto, eCPrivateKeyParameters);
        if (!SignatureScheme.isECDSA(i)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        if (signatureAndHashAlgorithm != null) {
            int from = SignatureScheme.from(signatureAndHashAlgorithm);
            int i = this.signatureScheme;
            if (from == i) {
                DSADigestSigner dSADigestSigner = new DSADigestSigner(new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i)))), new NullDigest());
                dSADigestSigner.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
                dSADigestSigner.update(bArr, 0, bArr.length);
                try {
                    return dSADigestSigner.generateSignature();
                } catch (CryptoException e) {
                    throw new TlsFatalAlert((short) 80, (Throwable) e);
                }
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
    }
}