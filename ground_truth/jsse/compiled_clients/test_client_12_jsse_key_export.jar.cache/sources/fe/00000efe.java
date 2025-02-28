package org.bouncycastle.util.p012io;

import java.io.IOException;
import java.io.OutputStream;

/* renamed from: org.bouncycastle.util.io.SimpleOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/SimpleOutputStream.class */
public abstract class SimpleOutputStream extends OutputStream {
    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() {
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() {
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        write(new byte[]{(byte) i}, 0, 1);
    }
}