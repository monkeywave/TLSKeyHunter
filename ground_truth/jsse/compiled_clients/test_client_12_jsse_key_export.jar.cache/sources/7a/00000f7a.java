package org.openjsse.javax.net.ssl;

import javax.net.ssl.SSLEngineResult;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/javax/net/ssl/SSLEngineResult.class */
public class SSLEngineResult extends javax.net.ssl.SSLEngineResult {
    private final long sequenceNumber;
    private final boolean needUnwrapAgain;

    public SSLEngineResult(SSLEngineResult.Status status, SSLEngineResult.HandshakeStatus handshakeStatus, int bytesConsumed, int bytesProduced) {
        this(status, handshakeStatus, bytesConsumed, bytesProduced, -1L, false);
    }

    public SSLEngineResult(SSLEngineResult.Status status, SSLEngineResult.HandshakeStatus handshakeStatus, int bytesConsumed, int bytesProduced, long sequenceNumber, boolean needUnwrapAgain) {
        super(status, handshakeStatus, bytesConsumed, bytesProduced);
        this.sequenceNumber = sequenceNumber;
        this.needUnwrapAgain = needUnwrapAgain;
    }

    public final long sequenceNumber() {
        return this.sequenceNumber;
    }

    public final boolean needUnwrapAgain() {
        return this.needUnwrapAgain;
    }

    @Override // javax.net.ssl.SSLEngineResult
    public String toString() {
        return super.toString() + (this.sequenceNumber == -1 ? "" : " sequenceNumber = " + Long.toUnsignedString(this.sequenceNumber));
    }
}