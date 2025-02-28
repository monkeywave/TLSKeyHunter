package org.bouncycastle.tls.crypto;

import java.io.IOException;
import org.bouncycastle.tls.SignatureAndHashAlgorithm;

/* loaded from: classes2.dex */
public interface TlsSigner {
    byte[] generateRawSignature(SignatureAndHashAlgorithm signatureAndHashAlgorithm, byte[] bArr) throws IOException;

    TlsStreamSigner getStreamSigner(SignatureAndHashAlgorithm signatureAndHashAlgorithm) throws IOException;
}