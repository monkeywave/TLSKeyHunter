package org.bouncycastle.jcajce.p006io;

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import org.bouncycastle.crypto.p005io.InvalidCipherTextIOException;

/* renamed from: org.bouncycastle.jcajce.io.CipherOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/io/CipherOutputStream.class */
public class CipherOutputStream extends FilterOutputStream {
    private final Cipher cipher;
    private final byte[] oneByte;

    public CipherOutputStream(OutputStream outputStream, Cipher cipher) {
        super(outputStream);
        this.oneByte = new byte[1];
        this.cipher = cipher;
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public void write(int i) throws IOException {
        this.oneByte[0] = (byte) i;
        write(this.oneByte, 0, 1);
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        byte[] update = this.cipher.update(bArr, i, i2);
        if (update != null) {
            this.out.write(update);
        }
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream, java.io.Flushable
    public void flush() throws IOException {
        this.out.flush();
    }

    @Override // java.io.FilterOutputStream, java.io.OutputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        InvalidCipherTextIOException invalidCipherTextIOException = null;
        try {
            byte[] doFinal = this.cipher.doFinal();
            if (doFinal != null) {
                this.out.write(doFinal);
            }
        } catch (GeneralSecurityException e) {
            invalidCipherTextIOException = new InvalidCipherTextIOException("Error during cipher finalisation", e);
        } catch (Exception e2) {
            invalidCipherTextIOException = new IOException("Error closing stream: " + e2);
        }
        try {
            flush();
            this.out.close();
        } catch (IOException e3) {
            if (invalidCipherTextIOException == null) {
                invalidCipherTextIOException = e3;
            }
        }
        if (invalidCipherTextIOException != null) {
            throw invalidCipherTextIOException;
        }
    }
}