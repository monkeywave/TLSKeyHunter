package org.bouncycastle.tls;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* loaded from: classes2.dex */
public interface TlsCredentialedSigner extends TlsCredentials {
    byte[] generateRawSignature(byte[] bArr) throws IOException;

    SignatureAndHashAlgorithm getSignatureAndHashAlgorithm();

    TlsStreamSigner getStreamSigner() throws IOException;
}