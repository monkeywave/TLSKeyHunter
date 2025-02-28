package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.engines.RSABlindedEngine;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.signers.PSSSigner;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsFatalAlert;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsRSAPSSSigner */
/* loaded from: classes2.dex */
public class BcTlsRSAPSSSigner extends BcTlsSigner {
    private final int signatureScheme;

    public BcTlsRSAPSSSigner(BcTlsCrypto bcTlsCrypto, RSAKeyParameters rSAKeyParameters, int i) {
        super(bcTlsCrypto, rSAKeyParameters);
        if (!SignatureScheme.isRSAPSS(i)) {
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
                PSSSigner createRawSigner = PSSSigner.createRawSigner(new RSABlindedEngine(), this.crypto.createDigest(SignatureScheme.getCryptoHashAlgorithm(i)));
                createRawSigner.init(true, new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()));
                createRawSigner.update(bArr, 0, bArr.length);
                try {
                    return createRawSigner.generateSignature();
                } catch (CryptoException e) {
                    throw new TlsFatalAlert((short) 80, (Throwable) e);
                }
            }
        }
        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
    }
}