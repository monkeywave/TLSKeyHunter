package org.openjsse.sun.security.provider;

import java.security.DigestException;
import java.security.MessageDigestSpi;
import java.security.ProviderException;
import java.util.Arrays;
import java.util.Objects;
import javassist.bytecode.Opcode;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/provider/DigestBase.class */
abstract class DigestBase extends MessageDigestSpi implements Cloneable {
    private byte[] oneByte;
    private final String algorithm;
    private final int digestLength;
    private final int blockSize;
    byte[] buffer;
    private int bufOfs;
    long bytesProcessed;
    static final byte[] padding = new byte[Opcode.L2I];

    abstract void implCompress(byte[] bArr, int i);

    abstract void implDigest(byte[] bArr, int i);

    abstract void implReset();

    /* JADX INFO: Access modifiers changed from: package-private */
    public DigestBase(String algorithm, int digestLength, int blockSize) {
        this.algorithm = algorithm;
        this.digestLength = digestLength;
        this.blockSize = blockSize;
        this.buffer = new byte[blockSize];
    }

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // java.security.MessageDigestSpi
    public final int engineGetDigestLength() {
        return this.digestLength;
    }

    @Override // java.security.MessageDigestSpi
    protected final void engineUpdate(byte b) {
        if (this.oneByte == null) {
            this.oneByte = new byte[1];
        }
        this.oneByte[0] = b;
        engineUpdate(this.oneByte, 0, 1);
    }

    @Override // java.security.MessageDigestSpi
    protected final void engineUpdate(byte[] b, int ofs, int len) {
        if (len == 0) {
            return;
        }
        if (ofs < 0 || len < 0 || ofs > b.length - len) {
            throw new ArrayIndexOutOfBoundsException();
        }
        if (this.bytesProcessed < 0) {
            engineReset();
        }
        this.bytesProcessed += len;
        if (this.bufOfs != 0) {
            int n = Math.min(len, this.blockSize - this.bufOfs);
            System.arraycopy(b, ofs, this.buffer, this.bufOfs, n);
            this.bufOfs += n;
            ofs += n;
            len -= n;
            if (this.bufOfs >= this.blockSize) {
                implCompress(this.buffer, 0);
                this.bufOfs = 0;
            }
        }
        if (len >= this.blockSize) {
            int limit = ofs + len;
            ofs = implCompressMultiBlock(b, ofs, limit - this.blockSize);
            len = limit - ofs;
        }
        if (len > 0) {
            System.arraycopy(b, ofs, this.buffer, 0, len);
            this.bufOfs = len;
        }
    }

    private int implCompressMultiBlock(byte[] b, int ofs, int limit) {
        implCompressMultiBlockCheck(b, ofs, limit);
        return implCompressMultiBlock0(b, ofs, limit);
    }

    private int implCompressMultiBlock0(byte[] b, int ofs, int limit) {
        while (ofs <= limit) {
            implCompress(b, ofs);
            ofs += this.blockSize;
        }
        return ofs;
    }

    private void implCompressMultiBlockCheck(byte[] b, int ofs, int limit) {
        if (limit < 0) {
            return;
        }
        Objects.requireNonNull(b);
        if (ofs < 0 || ofs >= b.length) {
            throw new ArrayIndexOutOfBoundsException(ofs);
        }
        int endIndex = (((limit / this.blockSize) * this.blockSize) + this.blockSize) - 1;
        if (endIndex >= b.length) {
            throw new ArrayIndexOutOfBoundsException(endIndex);
        }
    }

    @Override // java.security.MessageDigestSpi
    protected final void engineReset() {
        if (this.bytesProcessed == 0) {
            return;
        }
        implReset();
        this.bufOfs = 0;
        this.bytesProcessed = 0L;
        Arrays.fill(this.buffer, (byte) 0);
    }

    @Override // java.security.MessageDigestSpi
    protected final byte[] engineDigest() {
        byte[] b = new byte[this.digestLength];
        try {
            engineDigest(b, 0, b.length);
            return b;
        } catch (DigestException e) {
            throw ((ProviderException) new ProviderException("Internal error").initCause(e));
        }
    }

    @Override // java.security.MessageDigestSpi
    protected final int engineDigest(byte[] out, int ofs, int len) throws DigestException {
        if (len < this.digestLength) {
            throw new DigestException("Length must be at least " + this.digestLength + " for " + this.algorithm + "digests");
        }
        if (ofs < 0 || len < 0 || ofs > out.length - len) {
            throw new DigestException("Buffer too short to store digest");
        }
        if (this.bytesProcessed < 0) {
            engineReset();
        }
        implDigest(out, ofs);
        this.bytesProcessed = -1L;
        return this.digestLength;
    }

    @Override // java.security.MessageDigestSpi
    public Object clone() throws CloneNotSupportedException {
        DigestBase copy = (DigestBase) super.clone();
        copy.buffer = (byte[]) copy.buffer.clone();
        return copy;
    }

    static {
        padding[0] = Byte.MIN_VALUE;
    }
}