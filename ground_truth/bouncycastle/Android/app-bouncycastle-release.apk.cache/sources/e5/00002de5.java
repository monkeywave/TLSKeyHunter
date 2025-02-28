package org.bouncycastle.tls.crypto;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
public class TlsMACOutputStream extends OutputStream {
    protected TlsMAC mac;

    public TlsMACOutputStream(TlsMAC tlsMAC) {
        this.mac = tlsMAC;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.mac.update(new byte[]{(byte) i}, 0, 1);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.mac.update(bArr, i, i2);
    }
}