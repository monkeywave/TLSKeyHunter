package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;

/* loaded from: classes2.dex */
class NullOutputStream extends OutputStream {
    static final NullOutputStream INSTANCE = new NullOutputStream();

    private NullOutputStream() {
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
    }
}