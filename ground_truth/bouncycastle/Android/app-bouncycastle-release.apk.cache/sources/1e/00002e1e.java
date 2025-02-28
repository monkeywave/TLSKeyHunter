package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.tls.DigitallySigned;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsRSAPSSVerifier */
/* loaded from: classes2.dex */
public class BcTlsRSAPSSVerifier extends BcTlsVerifier {
    private final int signatureScheme;

    public BcTlsRSAPSSVerifier(BcTlsCrypto bcTlsCrypto, RSAKeyParameters rSAKeyParameters, int i) {
        super(bcTlsCrypto, rSAKeyParameters);
        if (!SignatureScheme.isRSAPSS(i)) {
            throw new IllegalArgumentException("signatureScheme");
        }
        this.signatureScheme = i;
    }

    @Override // org.bouncycastle.tls.crypto.TlsVerifier
    public boolean verifyRawSignature(DigitallySigned digitallySigned, byte[] bArr) throws IOException {
        SignatureAndHashAlgorithm algorithm = digitallySigned.getAlgorithm();
        if (algorithm != null) {
            int from = SignatureScheme.from(algorithm);
            int i = this.signatureScheme;
            if (from == i) {
                PSSSigner createRawSigner = PSSSigner.createRawSigner(new RSAEngine(), this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i)));
                createRawSigner.init(false, this.publicKey);
                createRawSigner.update(bArr, 0, bArr.length);
                return createRawSigner.verifySignature(digitallySigned.getSignature());
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + algorithm);
    }
}