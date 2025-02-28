package org.bouncycastle.jcajce.p012io;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;

/* renamed from: org.bouncycastle.jcajce.io.DigestUpdatingOutputStream */
/* loaded from: classes2.dex */
class DigestUpdatingOutputStream extends OutputStream {
    private MessageDigest digest;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DigestUpdatingOutputStream(MessageDigest messageDigest) {
        this.digest = messageDigest;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.digest.update((byte) i);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
        this.digest.update(bArr);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.digest.update(bArr, i, i2);
    }
}