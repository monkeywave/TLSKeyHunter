package org.bouncycastle.util.p012io;

import java.io.IOException;
import java.io.OutputStream;
import javassist.bytecode.AccessFlag;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.util.io.BufferingOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/BufferingOutputStream.class */
public class BufferingOutputStream extends OutputStream {
    private final OutputStream other;
    private final byte[] buf;
    private int bufOff;

    public BufferingOutputStream(OutputStream outputStream) {
        this.other = outputStream;
        this.buf = new byte[AccessFlag.SYNTHETIC];
    }

    public BufferingOutputStream(OutputStream outputStream, int i) {
        this.other = outputStream;
        this.buf = new byte[i];
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        int i3;
        if (i2 < this.buf.length - this.bufOff) {
            System.arraycopy(bArr, i, this.buf, this.bufOff, i2);
            this.bufOff += i2;
            return;
        }
        int length = this.buf.length - this.bufOff;
        System.arraycopy(bArr, i, this.buf, this.bufOff, length);
        this.bufOff += length;
        flush();
        int i4 = i + length;
        int i5 = i2;
        int i6 = length;
        while (true) {
            i3 = i5 - i6;
            if (i3 < this.buf.length) {
                break;
            }
            this.other.write(bArr, i4, this.buf.length);
            i4 += this.buf.length;
            i5 = i3;
            i6 = this.buf.length;
        }
        if (i3 > 0) {
            System.arraycopy(bArr, i4, this.buf, this.bufOff, i3);
            this.bufOff += i3;
        }
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        byte[] bArr = this.buf;
        int i2 = this.bufOff;
        this.bufOff = i2 + 1;
        bArr[i2] = (byte) i;
        if (this.bufOff == this.buf.length) {
            flush();
        }
    }

    @Override // java.io.OutputStream, java.io.Flushable
    public void flush() throws IOException {
        this.other.write(this.buf, 0, this.bufOff);
        this.bufOff = 0;
        Arrays.fill(this.buf, (byte) 0);
    }

    @Override // java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        flush();
        this.other.close();
    }
}