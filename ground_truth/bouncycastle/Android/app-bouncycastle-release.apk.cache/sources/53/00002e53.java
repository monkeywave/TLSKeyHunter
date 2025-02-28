package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.jcajce.p012io.OutputStreamFactory;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

/* loaded from: classes2.dex */
class JcaTlsStreamVerifier implements TlsStreamVerifier {
    private final OutputStream output;
    private final byte[] signature;
    private final Signature verifier;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JcaTlsStreamVerifier(Signature signature, byte[] bArr) {
        this.verifier = signature;
        this.output = OutputStreamFactory.createStream(signature);
        this.signature = bArr;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
    public boolean isVerified() throws IOException {
        try {
            return this.verifier.verify(this.signature);
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}