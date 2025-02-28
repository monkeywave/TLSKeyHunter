package org.bouncycastle.crypto.p005io;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.Signer;

/* renamed from: org.bouncycastle.crypto.io.SignerOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/io/SignerOutputStream.class */
public class SignerOutputStream extends OutputStream {
    protected Signer signer;

    public SignerOutputStream(Signer signer) {
        this.signer = signer;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.signer.update((byte) i);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.signer.update(bArr, i, i2);
    }

    public Signer getSigner() {
        return this.signer;
    }
}