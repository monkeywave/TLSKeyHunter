package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.CryptoException;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.p011io.SignerOutputStream;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.TlsStreamSigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsStreamSigner */
/* loaded from: classes2.dex */
class BcTlsStreamSigner implements TlsStreamSigner {
    private final SignerOutputStream output;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsStreamSigner(Signer signer) {
        this.output = new SignerOutputStream(signer);
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamSigner
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamSigner
    public byte[] getSignature() throws IOException {
        try {
            return this.output.getSigner().generateSignature();
        } catch (CryptoException e) {
            throw new TlsFatalAlert((short) 80, (Throwable) e);
        }
    }
}