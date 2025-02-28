package org.bouncycastle.jcajce.p006io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.Signature;
import java.security.SignatureException;

/* renamed from: org.bouncycastle.jcajce.io.SignatureUpdatingOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/io/SignatureUpdatingOutputStream.class */
class SignatureUpdatingOutputStream extends OutputStream {
    private Signature sig;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SignatureUpdatingOutputStream(Signature signature) {
        this.sig = signature;
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        try {
            this.sig.update(bArr, i, i2);
        } catch (SignatureException e) {
            throw new IOException(e.getMessage());
        }
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
        try {
            this.sig.update(bArr);
        } catch (SignatureException e) {
            throw new IOException(e.getMessage());
        }
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        try {
            this.sig.update((byte) i);
        } catch (SignatureException e) {
            throw new IOException(e.getMessage());
        }
    }
}