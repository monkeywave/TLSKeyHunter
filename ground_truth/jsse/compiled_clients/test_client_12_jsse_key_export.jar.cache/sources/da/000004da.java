package org.bouncycastle.crypto.p005io;

import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.crypto.Mac;

/* renamed from: org.bouncycastle.crypto.io.MacOutputStream */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/io/MacOutputStream.class */
public class MacOutputStream extends OutputStream {
    protected Mac mac;

    public MacOutputStream(Mac mac) {
        this.mac = mac;
    }

    @Override // java.io.OutputStream
    public void write(int i) throws IOException {
        this.mac.update((byte) i);
    }

    @Override // java.io.OutputStream
    public void write(byte[] bArr, int i, int i2) throws IOException {
        this.mac.update(bArr, i, i2);
    }

    public byte[] getMac() {
        byte[] bArr = new byte[this.mac.getMacSize()];
        this.mac.doFinal(bArr, 0);
        return bArr;
    }
}