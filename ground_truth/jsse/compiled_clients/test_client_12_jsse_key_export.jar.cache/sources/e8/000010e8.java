package org.openjsse.sun.security.ssl;

import java.nio.ByteBuffer;
import javax.net.ssl.SSLEngineResult;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/Plaintext.class */
final class Plaintext {
    static final Plaintext PLAINTEXT_NULL = new Plaintext();
    final byte contentType;
    final byte majorVersion;
    final byte minorVersion;
    final int recordEpoch;
    final long recordSN;
    final ByteBuffer fragment;
    SSLEngineResult.HandshakeStatus handshakeStatus;

    private Plaintext() {
        this.contentType = (byte) 0;
        this.majorVersion = (byte) 0;
        this.minorVersion = (byte) 0;
        this.recordEpoch = -1;
        this.recordSN = -1L;
        this.fragment = null;
        this.handshakeStatus = null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Plaintext(byte contentType, byte majorVersion, byte minorVersion, int recordEpoch, long recordSN, ByteBuffer fragment) {
        this.contentType = contentType;
        this.majorVersion = majorVersion;
        this.minorVersion = minorVersion;
        this.recordEpoch = recordEpoch;
        this.recordSN = recordSN;
        this.fragment = fragment;
        this.handshakeStatus = null;
    }

    public String toString() {
        return "contentType: " + ((int) this.contentType) + "/majorVersion: " + ((int) this.majorVersion) + "/minorVersion: " + ((int) this.minorVersion) + "/recordEpoch: " + this.recordEpoch + "/recordSN: 0x" + Long.toHexString(this.recordSN) + "/fragment: " + this.fragment;
    }
}