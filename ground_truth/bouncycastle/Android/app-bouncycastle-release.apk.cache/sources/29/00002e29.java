package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.p011io.SignerOutputStream;
import org.bouncycastle.tls.crypto.TlsStreamVerifier;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsStreamVerifier */
/* loaded from: classes2.dex */
class BcTlsStreamVerifier implements TlsStreamVerifier {
    private final SignerOutputStream output;
    private final byte[] signature;

    BcTlsStreamVerifier(Signer signer, byte[] bArr) {
        this.output = new SignerOutputStream(signer);
        this.signature = bArr;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
    public OutputStream getOutputStream() throws IOException {
        return this.output;
    }

    @Override // org.bouncycastle.tls.crypto.TlsStreamVerifier
    public boolean isVerified() throws IOException {
        return this.output.getSigner().verifySignature(this.signature);
    }
}