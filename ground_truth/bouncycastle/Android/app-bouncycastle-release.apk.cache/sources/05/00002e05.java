package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.p011io.SignerOutputStream;
import org.bouncycastle.tls.crypto.Tls13Verifier;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTls13Verifier */
/* loaded from: classes2.dex */
final class BcTls13Verifier implements Tls13Verifier {
    private final SignerOutputStream output;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTls13Verifier(Signer signer) {
        if (signer == null) {
            throw new NullPointerException("'verifier' cannot be null");
        }
        this.output = new SignerOutputStream(signer);
    }

    @Override // org.bouncycastle.tls.crypto.Tls13Verifier
    public final OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.Tls13Verifier
    public final boolean verifySignature(byte[] bArr) throws IOException {
        return this.output.getSigner().verifySignature(bArr);
    }
}