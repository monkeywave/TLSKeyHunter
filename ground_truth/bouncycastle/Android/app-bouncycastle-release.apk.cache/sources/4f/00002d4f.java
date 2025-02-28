package org.bouncycastle.tls;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class HandshakeMessageOutput extends ByteArrayOutputStream {
    /* JADX INFO: Access modifiers changed from: package-private */
    public HandshakeMessageOutput(short s) throws IOException {
        this(s, 60);
    }

    HandshakeMessageOutput(short s, int i) throws IOException {
        super(getLength(i));
        TlsUtils.checkUint8(s);
        TlsUtils.writeUint8(s, (OutputStream) this);
        this.count += 3;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int getLength(int i) {
        return i + 4;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static void send(TlsProtocol tlsProtocol, short s, byte[] bArr) throws IOException {
        HandshakeMessageOutput handshakeMessageOutput = new HandshakeMessageOutput(s, bArr.length);
        handshakeMessageOutput.write(bArr);
        handshakeMessageOutput.send(tlsProtocol);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void prepareClientHello(TlsHandshakeHash tlsHandshakeHash, int i) throws IOException {
        int i2 = (this.count - 4) + i;
        TlsUtils.checkUint24(i2);
        TlsUtils.writeUint24(i2, this.buf, 1);
        tlsHandshakeHash.update(this.buf, 0, this.count);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void send(TlsProtocol tlsProtocol) throws IOException {
        int i = this.count - 4;
        TlsUtils.checkUint24(i);
        TlsUtils.writeUint24(i, this.buf, 1);
        tlsProtocol.writeHandshakeMessage(this.buf, 0, this.count);
        this.buf = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void sendClientHello(TlsClientProtocol tlsClientProtocol, TlsHandshakeHash tlsHandshakeHash, int i) throws IOException {
        if (i > 0) {
            tlsHandshakeHash.update(this.buf, this.count - i, i);
        }
        tlsClientProtocol.writeHandshakeMessage(this.buf, 0, this.count);
        this.buf = null;
    }
}