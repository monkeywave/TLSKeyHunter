package org.openjsse.sun.security.ssl;

import javax.net.ssl.SSLEngineResult;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Ciphertext.class */
final class Ciphertext {
    final byte contentType;
    final byte handshakeType;
    final long recordSN;
    SSLEngineResult.HandshakeStatus handshakeStatus;

    private Ciphertext() {
        this.contentType = (byte) 0;
        this.handshakeType = (byte) -1;
        this.recordSN = -1L;
        this.handshakeStatus = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Ciphertext(byte contentType, byte handshakeType, long recordSN) {
        this.contentType = contentType;
        this.handshakeType = handshakeType;
        this.recordSN = recordSN;
        this.handshakeStatus = null;
    }
}