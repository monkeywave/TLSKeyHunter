package org.bouncycastle.tls;

import java.io.IOException;
import java.io.InputStream;
import kotlin.UByte;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TlsInputStream extends InputStream {
    private final TlsProtocol handler;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsInputStream(TlsProtocol tlsProtocol) {
        this.handler = tlsProtocol;
    }

    @Override // java.io.InputStream
    public int available() throws IOException {
        return this.handler.applicationDataAvailable();
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.handler.close();
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        byte[] bArr = new byte[1];
        if (read(bArr, 0, 1) <= 0) {
            return -1;
        }
        return bArr[0] & UByte.MAX_VALUE;
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i, int i2) throws IOException {
        return this.handler.readApplicationData(bArr, i, i2);
    }
}