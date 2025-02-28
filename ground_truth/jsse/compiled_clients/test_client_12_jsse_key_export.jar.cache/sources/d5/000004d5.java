package org.bouncycastle.crypto.p005io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.modes.AEADBlockCipher;

/* renamed from: org.bouncycastle.crypto.io.CipherOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/io/CipherOutputStream.class */
public class CipherOutputStream extends FilterOutputStream {
    private BufferedBlockCipher bufferedBlockCipher;
    private StreamCipher streamCipher;
    private AEADBlockCipher aeadBlockCipher;
    private final byte[] oneByte;
    private byte[] buf;

    public CipherOutputStream(OutputStream outputStream, BufferedBlockCipher bufferedBlockCipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.bufferedBlockCipher = bufferedBlockCipher;
    }

    public CipherOutputStream(OutputStream outputStream, StreamCipher streamCipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.streamCipher = streamCipher;
    }

    public CipherOutputStream(OutputStream outputStream, AEADBlockCipher aEADBlockCipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.aeadBlockCipher = aEADBlockCipher;
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public void write(int i) throws IOException {
        this.oneByte[0] = (byte) i;
        if (this.streamCipher != null) {
            this.out.write(this.streamCipher.returnByte((byte) i));
        } else {
            write(this.oneByte, 0, 1);
        }
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
        write(bArr, 0, bArr.length);
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        ensureCapacity(i2, false);
        if (this.bufferedBlockCipher != null) {
            int processBytes = this.bufferedBlockCipher.processBytes(bArr, i, i2, this.buf, 0);
            if (processBytes != 0) {
                this.out.write(this.buf, 0, processBytes);
            }
        } else if (this.aeadBlockCipher == null) {
            this.streamCipher.processBytes(bArr, i, i2, this.buf, 0);
            this.out.write(this.buf, 0, i2);
        } else {
            int processBytes2 = this.aeadBlockCipher.processBytes(bArr, i, i2, this.buf, 0);
            if (processBytes2 != 0) {
                this.out.write(this.buf, 0, processBytes2);
            }
        }
    }

    private void ensureCapacity(int i, boolean z) {
        int i2 = i;
        if (z) {
            if (this.bufferedBlockCipher != null) {
                i2 = this.bufferedBlockCipher.getOutputSize(i);
            } else if (this.aeadBlockCipher != null) {
                i2 = this.aeadBlockCipher.getOutputSize(i);
            }
        } else if (this.bufferedBlockCipher != null) {
            i2 = this.bufferedBlockCipher.getUpdateOutputSize(i);
        } else if (this.aeadBlockCipher != null) {
            i2 = this.aeadBlockCipher.getUpdateOutputSize(i);
        }
        if (this.buf == null || this.buf.length < i2) {
            this.buf = new byte[i2];
        }
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream, java.io.Flushable
    public void flush() throws IOException {
        this.out.flush();
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        ensureCapacity(0, true);
        Throwable th = null;
        try {
            if (this.bufferedBlockCipher != null) {
                int doFinal = this.bufferedBlockCipher.doFinal(this.buf, 0);
                if (doFinal != 0) {
                    this.out.write(this.buf, 0, doFinal);
                }
            } else if (this.aeadBlockCipher != null) {
                int doFinal2 = this.aeadBlockCipher.doFinal(this.buf, 0);
                if (doFinal2 != 0) {
                    this.out.write(this.buf, 0, doFinal2);
                }
            } else if (this.streamCipher != null) {
                this.streamCipher.reset();
            }
        } catch (InvalidCipherTextException e) {
            th = new InvalidCipherTextIOException("Error finalising cipher data", e);
        } catch (Exception e2) {
            th = new CipherIOException("Error closing stream: ", e2);
        }
        try {
            flush();
            this.out.close();
        } catch (IOException e3) {
            if (th == null) {
                th = e3;
            }
        }
        if (th != null) {
            throw th;
        }
    }
}