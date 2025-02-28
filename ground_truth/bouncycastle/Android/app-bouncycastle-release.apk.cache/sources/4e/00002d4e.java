package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import org.bouncycastle.tls.crypto.TlsHash;

/* loaded from: classes2.dex */
public class HandshakeMessageInput extends ByteArrayInputStream {
    /* JADX INFO: Access modifiers changed from: package-private */
    public HandshakeMessageInput(byte[] bArr, int i, int i2) {
        super(bArr, i, i2);
    }

    @Override // java.io.ByteArrayInputStream, java.io.InputStream
    public void mark(int i) {
        throw new UnsupportedOperationException();
    }

    @Override // java.io.ByteArrayInputStream, java.io.InputStream
    public boolean markSupported() {
        return false;
    }

    public void updateHash(TlsHash tlsHash) {
        tlsHash.update(this.buf, this.mark, this.count - this.mark);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateHashPrefix(TlsHash tlsHash, int i) {
        tlsHash.update(this.buf, this.mark, (this.count - this.mark) - i);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateHashSuffix(TlsHash tlsHash, int i) {
        tlsHash.update(this.buf, this.count - i, i);
    }
}