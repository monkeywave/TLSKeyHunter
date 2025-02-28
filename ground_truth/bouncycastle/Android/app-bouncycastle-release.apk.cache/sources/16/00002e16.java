package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.params.Ed448PrivateKeyParameters;
import org.bouncycastle.crypto.signers.Ed448Signer;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsEd448Signer */
/* loaded from: classes2.dex */
public class BcTlsEd448Signer extends BcTlsSigner {
    public BcTlsEd448Signer(BcTlsCrypto bcTlsCrypto, Ed448PrivateKeyParameters ed448PrivateKeyParameters) {
        super(bcTlsCrypto, ed448PrivateKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsSigner, org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (signatureAndHashAlgorithm == null || SignatureScheme.from(signatureAndHashAlgorithm) != 2056) {
            throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
        }
        Ed448Signer ed448Signer = new Ed448Signer(TlsUtils.EMPTY_BYTES);
        ed448Signer.init(true, this.privateKey);
        return new BcTlsStreamSigner(ed448Signer);
    }
}