package org.bouncycastle.crypto.p011io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import org.bouncycastle.crypto.Signer;

/* renamed from: org.bouncycastle.crypto.io.SignerInputStream */
/* loaded from: classes2.dex */
public class SignerInputStream extends FilterInputStream {
    protected Signer signer;

    public SignerInputStream(InputStream inputStream, Signer signer) {
        super(inputStream);
        this.signer = signer;
    }

    public Signer getSigner() {
        return this.signer;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() throws IOException {
        int read = this.in.read();
        if (read >= 0) {
            this.signer.update((byte) read);
        }
        return read;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr, int i, int i2) throws IOException {
        int read = this.in.read(bArr, i, i2);
        if (read > 0) {
            this.signer.update(bArr, i, read);
        }
        return read;
    }
}