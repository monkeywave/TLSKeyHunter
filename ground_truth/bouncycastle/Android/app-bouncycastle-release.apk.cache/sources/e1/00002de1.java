package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class TlsHashOutputStream extends OutputStream {
    protected TlsHash hash;

    public TlsHashOutputStream(TlsHash tlsHash) {
        this.hash = tlsHash;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.hash.update(new byte[]{(byte) i}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.hash.update(bArr, i, i2);
    }
}