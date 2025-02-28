package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.jcajce.p012io.OutputStreamFactory;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* loaded from: classes2.dex */
class JcaTlsStreamSigner implements TlsStreamSigner {
    private final OutputStream output;
    private final Signature signer;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JcaTlsStreamSigner(Signature signature) {
        this.signer = signature;
        this.output = OutputStreamFactory.createStream(signature);
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamSigner
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamSigner
    public byte[] getSignature() throws IOException {
        try {
            return this.signer.sign();
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}