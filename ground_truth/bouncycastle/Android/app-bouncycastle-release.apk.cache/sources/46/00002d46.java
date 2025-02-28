package org.bouncycastle.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.p019io.Streams;

/* loaded from: classes2.dex */
class DigestInputBuffer extends ByteArrayOutputStream {
    /* JADX INFO: Access modifiers changed from: package-private */
    public void copyInputTo(OutputStream outputStream) throws IOException {
        Streams.pipeAll(new ByteArrayInputStream(this.buf, 0, this.count), outputStream);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void updateDigest(TlsHash tlsHash) {
        tlsHash.update(this.buf, 0, this.count);
    }
}