package org.bouncycastle.jcajce.p012io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import kotlin.UByte;
import org.bouncycastle.crypto.p011io.InvalidCipherTextIOException;

/* renamed from: org.bouncycastle.jcajce.io.CipherInputStream */
/* loaded from: classes2.dex */
public class CipherInputStream extends FilterInputStream {
    private byte[] buf;
    private int bufOff;
    private final Cipher cipher;
    private boolean finalized;
    private final byte[] inputBuffer;
    private int maxBuf;

    public CipherInputStream(InputStream inputStream, Cipher cipher) {
        super(inputStream);
        this.inputBuffer = new byte[512];
        this.finalized = false;
        this.cipher = cipher;
    }

    private byte[] finaliseCipher() throws InvalidCipherTextIOException {
        try {
            if (this.finalized) {
                return null;
            }
            this.finalized = true;
            return this.cipher.doFinal();
        } catch (GeneralSecurityException e) {
            throw new InvalidCipherTextIOException("Error finalising cipher", e);
        }
    }

    private int nextChunk() throws IOException {
        if (this.finalized) {
            return -1;
        }
        this.bufOff = 0;
        this.maxBuf = 0;
        while (true) {
            int i = this.maxBuf;
            if (i != 0) {
                return i;
            }
            int read = this.in.read(this.inputBuffer);
            if (read == -1) {
                byte[] finaliseCipher = finaliseCipher();
                this.buf = finaliseCipher;
                if (finaliseCipher == null || finaliseCipher.length == 0) {
                    return -1;
                }
                int length = finaliseCipher.length;
                this.maxBuf = length;
                return length;
            }
            byte[] update = this.cipher.update(this.inputBuffer, 0, read);
            this.buf = update;
            if (update != null) {
                this.maxBuf = update.length;
            }
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int available() throws IOException {
        return this.maxBuf - this.bufOff;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream, java.io.Closeable, java.lang.AutoCloseable
    public void close() throws IOException {
        try {
            this.in.close();
            this.bufOff = 0;
            this.maxBuf = 0;
        } finally {
            if (!this.finalized) {
                finaliseCipher();
            }
        }
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void mark(int i) {
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public boolean markSupported() {
        return false;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read() throws IOException {
        if (this.bufOff < this.maxBuf || nextChunk() >= 0) {
            byte[] bArr = this.buf;
            int i = this.bufOff;
            this.bufOff = i + 1;
            return bArr[i] & UByte.MAX_VALUE;
        }
        return -1;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public int read(byte[] bArr, int i, int i2) throws IOException {
        if (this.bufOff < this.maxBuf || nextChunk() >= 0) {
            int min = Math.min(i2, available());
            System.arraycopy(this.buf, this.bufOff, bArr, i, min);
            this.bufOff += min;
            return min;
        }
        return -1;
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public void reset() throws IOException {
    }

    @Override // java.io.FilterInputStream, java.io.InputStream
    public long skip(long j) throws IOException {
        if (j <= 0) {
            return 0L;
        }
        int min = (int) Math.min(j, available());
        this.bufOff += min;
        return min;
    }
}