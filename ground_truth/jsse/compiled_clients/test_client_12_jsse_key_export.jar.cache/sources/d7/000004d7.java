package org.bouncycastle.crypto.p005io;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.Digest;

/* renamed from: org.bouncycastle.crypto.io.DigestOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/io/DigestOutputStream.class */
public class DigestOutputStream extends OutputStream {
    protected Digest digest;

    public DigestOutputStream(Digest digest) {
        this.digest = digest;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.digest.update((byte) i);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.digest.update(bArr, i, i2);
    }

    public byte[] getDigest() {
        byte[] bArr = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr, 0);
        return bArr;
    }
}