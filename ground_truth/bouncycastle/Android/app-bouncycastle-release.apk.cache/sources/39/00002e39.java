package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;
import org.bouncycastle.jcajce.p012io.OutputStreamFactory;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.Tls13Verifier;

/* loaded from: classes2.dex */
final class JcaTls13Verifier implements Tls13Verifier {
    private final OutputStream output;
    private final Signature verifier;

    /* JADX INFO: Access modifiers changed from: package-private */
    public JcaTls13Verifier(Signature signature) {
        this.verifier = signature;
        this.output = OutputStreamFactory.createStream(signature);
    }

    @Override // org.bouncycastle.tls.crypto.Tls13Verifier
    public final OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.Tls13Verifier
    public final boolean verifySignature(byte[] bArr) throws IOException {
        try {
            return this.verifier.verify(bArr);
        } catch (SignatureException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}