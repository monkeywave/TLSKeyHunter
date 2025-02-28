package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ParametersWithID;
import org.bouncycastle.crypto.params.ParametersWithRandom;
import org.bouncycastle.crypto.signers.SM2Signer;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;
import org.bouncycastle.tls.crypto.TlsStreamSigner;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsSM2Signer */
/* loaded from: classes2.dex */
public class BcTlsSM2Signer extends BcTlsSigner {
    protected final byte[] identifier;

    public BcTlsSM2Signer(BcTlsCrypto bcTlsCrypto, ECPrivateKeyParameters eCPrivateKeyParameters, byte[] bArr) {
        super(bcTlsCrypto, eCPrivateKeyParameters);
        this.identifier = Arrays.clone(bArr);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSigner
    public byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException {
        throw new UnsupportedOperationException();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsSigner, org.bouncycastle.tls.crypto.TlsSigner
    public TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) {
        if (signatureAndHashAlgorithm != null) {
            ParametersWithID parametersWithID = new ParametersWithID(new ParametersWithRandom(this.privateKey, this.crypto.getSecureRandom()), this.identifier);
            SM2Signer sM2Signer = new SM2Signer();
            sM2Signer.init(true, parametersWithID);
            return new BcTlsStreamSigner(sM2Signer);
        }
        throw new IllegalStateException("Invalid algorithm: " + signatureAndHashAlgorithm);
    }
}