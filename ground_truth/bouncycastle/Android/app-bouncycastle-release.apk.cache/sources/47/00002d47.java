package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public final class DigitallySigned {
    private final SignatureAndHashAlgorithm algorithm;
    private final byte[] signature;

    public DigitallySigned(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) {
        if (bArr == null) {
            throw new IllegalArgumentException("'signature' cannot be null");
        }
        this.algorithm = signatureAndHashAlgorithm;
        this.signature = bArr;
    }

    public static DigitallySigned parse(TlsContext tlsContext, InputStream inputStream) throws IOException {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm;
        if (TlsUtils.isTLSv12(tlsContext)) {
            signatureAndHashAlgorithm = SignatureAndHashAlgorithm.parse(inputStream);
            if (signatureAndHashAlgorithm.getSignature() == 0) {
                throw new TlsFatalAlert((short) 47);
            }
        } else {
            signatureAndHashAlgorithm = null;
        }
        return new DigitallySigned(signatureAndHashAlgorithm, TlsUtils.readOpaque16(inputStream));
    }

    public void encode(OutputStream outputStream) throws IOException {
        SignatureAndHashAlgorithm signatureAndHashAlgorithm = this.algorithm;
        if (signatureAndHashAlgorithm != null) {
            signatureAndHashAlgorithm.encode(outputStream);
        }
        TlsUtils.writeOpaque16(this.signature, outputStream);
    }

    public SignatureAndHashAlgorithm getAlgorithm() {
        return this.algorithm;
    }

    public byte[] getSignature() {
        return this.signature;
    }
}