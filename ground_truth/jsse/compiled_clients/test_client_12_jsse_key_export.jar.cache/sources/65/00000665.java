package org.bouncycastle.jcajce.p006io;

import java.io.IOException;
import java.io.OutputStream;
import javax.crypto.Mac;

/* renamed from: org.bouncycastle.jcajce.io.MacUpdatingOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/io/MacUpdatingOutputStream.class */
class MacUpdatingOutputStream extends OutputStream {
    private Mac mac;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MacUpdatingOutputStream(Mac mac) {
        this.mac = mac;
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.mac.update(bArr, i, i2);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr) throws IOException {
        this.mac.update(bArr);
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.mac.update((byte) i);
    }
}