package org.bouncycastle.jcajce.p006io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

/* renamed from: org.bouncycastle.jcajce.io.DigestUpdatingOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/io/DigestUpdatingOutputStream.class */
class DigestUpdatingOutputStream extends OutputStream {
    private MessageDigest digest;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DigestUpdatingOutputStream(MessageDigest messageDigest) {
        this.digest = messageDigest;
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.digest.update(bArr, i, i2);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
        this.digest.update(bArr);
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.digest.update((byte) i);
    }
}