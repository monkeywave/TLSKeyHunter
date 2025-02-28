package org.openjsse.sun.security.ssl;

import java.security.SecureRandom;
import java.util.Arrays;
import javax.net.ssl.SSLProtocolException;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/SessionId.class */
final class SessionId {
    private static final int MAX_LENGTH = 32;
    private final byte[] sessionId;

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionId(boolean isRejoinable, SecureRandom generator) {
        if (isRejoinable && generator != null) {
            this.sessionId = new RandomCookie(generator).randomBytes;
        } else {
            this.sessionId = new byte[0];
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public SessionId(byte[] sessionId) {
        this.sessionId = (byte[]) sessionId.clone();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int length() {
        return this.sessionId.length;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] getId() {
        return (byte[]) this.sessionId.clone();
    }

    public String toString() {
        if (this.sessionId.length == 0) {
            return "";
        }
        return Utilities.toHexString(this.sessionId);
    }

    public int hashCode() {
        return Arrays.hashCode(this.sessionId);
    }

    public boolean equals(Object obj) {
        if (obj == this) {
            return true;
        }
        if (obj instanceof SessionId) {
            SessionId that = (SessionId) obj;
            return Arrays.equals(this.sessionId, that.sessionId);
        }
        return false;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void checkLength(int protocolVersion) throws SSLProtocolException {
        if (this.sessionId.length > 32) {
            throw new SSLProtocolException("Invalid session ID length (" + this.sessionId.length + " bytes)");
        }
    }
}