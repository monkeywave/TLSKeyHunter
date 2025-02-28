package org.bouncycastle.util.p012io;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/* renamed from: org.bouncycastle.util.io.TeeInputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/TeeInputStream.class */
public class TeeInputStream extends InputStream {
    private final InputStream input;
    private final OutputStream output;

    public TeeInputStream(InputStream inputStream, OutputStream outputStream) {
        this.input = inputStream;
        this.output = outputStream;
    }

    @Override // java.io.InputStream
    public int available() throws IOException {
        return this.input.available();
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr) throws IOException {
        return read(bArr, 0, bArr.length);
    }

    @Override // java.io.InputStream
    public int read(byte[] bArr, int i, int i2) throws IOException {
        int read = this.input.read(bArr, i, i2);
        if (read > 0) {
            this.output.write(bArr, i, read);
        }
        return read;
    }

    @Override // java.io.InputStream
    public int read() throws IOException {
        int read = this.input.read();
        if (read >= 0) {
            this.output.write(read);
        }
        return read;
    }

    @Override // java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        this.input.close();
        this.output.close();
    }

    public OutputStream getOutputStream() {
        return this.output;
    }
}